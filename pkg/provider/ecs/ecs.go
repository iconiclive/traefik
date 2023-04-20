package ecs

import (
	"context"
	"fmt"
	"strings"
	"text/template"
	"time"
	"io/ioutil"
	"os"
	"encoding/json"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/cenkalti/backoff/v4"
	"github.com/patrickmn/go-cache"
	"github.com/traefik/traefik/v2/pkg/config/dynamic"
	"github.com/traefik/traefik/v2/pkg/job"
	"github.com/traefik/traefik/v2/pkg/log"
	"github.com/traefik/traefik/v2/pkg/provider"
	"github.com/traefik/traefik/v2/pkg/safe"
	"github.com/gofrs/flock"
)

// Provider holds configurations of the provider.
type Provider struct {
	Constraints      string `description:"Constraints is an expression that Traefik matches against the container's labels to determine whether to create any route for that container." json:"constraints,omitempty" toml:"constraints,omitempty" yaml:"constraints,omitempty" export:"true"`
	ExposedByDefault bool   `description:"Expose services by default." json:"exposedByDefault,omitempty" toml:"exposedByDefault,omitempty" yaml:"exposedByDefault,omitempty" export:"true"`
	RefreshSeconds   int    `description:"Polling interval (in seconds)." json:"refreshSeconds,omitempty" toml:"refreshSeconds,omitempty" yaml:"refreshSeconds,omitempty" export:"true"`
	DefaultRule      string `description:"Default rule." json:"defaultRule,omitempty" toml:"defaultRule,omitempty" yaml:"defaultRule,omitempty"`

	// Provider lookup parameters.
	Clusters             []string `description:"ECS Cluster names." json:"clusters,omitempty" toml:"clusters,omitempty" yaml:"clusters,omitempty" export:"true"`
	AutoDiscoverClusters bool     `description:"Auto discover cluster." json:"autoDiscoverClusters,omitempty" toml:"autoDiscoverClusters,omitempty" yaml:"autoDiscoverClusters,omitempty" export:"true"`
	HealthyTasksOnly     bool     `description:"Determines whether to discover only healthy tasks." json:"healthyTasksOnly,omitempty" toml:"healthyTasksOnly,omitempty" yaml:"healthyTasksOnly,omitempty" export:"true"`
	ECSAnywhere          bool     `description:"Enable ECS Anywhere support." json:"ecsAnywhere,omitempty" toml:"ecsAnywhere,omitempty" yaml:"ecsAnywhere,omitempty" export:"true"`
	Region               string   `description:"AWS region to use for requests."  json:"region,omitempty" toml:"region,omitempty" yaml:"region,omitempty" export:"true"`
	AccessKeyID          string   `description:"AWS credentials access key ID to use for making requests." json:"accessKeyID,omitempty" toml:"accessKeyID,omitempty" yaml:"accessKeyID,omitempty" loggable:"false"`
	SecretAccessKey      string   `description:"AWS credentials access key to use for making requests." json:"secretAccessKey,omitempty" toml:"secretAccessKey,omitempty" yaml:"secretAccessKey,omitempty" loggable:"false"`
	defaultRuleTpl       *template.Template
}

type ecsInstance struct {
	Name                string
	ID                  string
	containerDefinition *ecs.ContainerDefinition
	machine             *machine
	Labels              map[string]string
	ExtraConf           configuration
}

func (e ecsInstance) MarshalJSON() ([]byte, error) {
	type Alias ecsInstance

	return json.Marshal(&struct {
		ContainerDefinition *ecs.ContainerDefinition `json:"containerDefinition"`
		Machine             *machine                 `json:"machine"`
		*Alias
	}{
		ContainerDefinition: e.containerDefinition,
		Machine:             e.machine,
		Alias:               (*Alias)(&e),
	})
}

func (e *ecsInstance) UnmarshalJSON(data []byte) error {
	type Alias ecsInstance

	aux := &struct {
		ContainerDefinition json.RawMessage `json:"containerDefinition"`
		Machine             json.RawMessage `json:"machine"`
		*Alias
	}{
		Alias: (*Alias)(e),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	var containerDefinition ecs.ContainerDefinition
	if err := json.Unmarshal(aux.ContainerDefinition, &containerDefinition); err != nil {
		return err
	}
	e.containerDefinition = &containerDefinition

	var machine machine
	if err := json.Unmarshal(aux.Machine, &machine); err != nil {
		return err
	}
	e.machine = &machine

	return nil
}

type portMapping struct {
	containerPort int64
	hostPort      int64
	protocol      string
}

func (p portMapping) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ContainerPort int64  `json:"containerPort"`
		HostPort      int64  `json:"hostPort"`
		Protocol      string `json:"protocol"`
	}{
		ContainerPort: p.containerPort,
		HostPort:      p.hostPort,
		Protocol:      p.protocol,
	})
}

func (p *portMapping) UnmarshalJSON(data []byte) error {
	aux := &struct {
		ContainerPort int64  `json:"containerPort"`
		HostPort      int64  `json:"hostPort"`
		Protocol      string `json:"protocol"`
	}{}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	p.containerPort = aux.ContainerPort
	p.hostPort = aux.HostPort
	p.protocol = aux.Protocol

	return nil
}

type machine struct {
	state        string
	privateIP    string
	ports        []portMapping
	healthStatus string
}

func (m machine) MarshalJSON() ([]byte, error) {
	type Alias machine

	return json.Marshal(&struct {
		State        string        `json:"state"`
		PrivateIP    string        `json:"privateIP"`
		Ports        []portMapping `json:"ports"`
		HealthStatus string        `json:"healthStatus"`
		*Alias
	}{
		State:        m.state,
		PrivateIP:    m.privateIP,
		Ports:        m.ports,
		HealthStatus: m.healthStatus,
		Alias:        (*Alias)(&m),
	})
}

func (m *machine) UnmarshalJSON(data []byte) error {
	type Alias machine

	aux := &struct {
		State        string        `json:"state"`
		PrivateIP    string        `json:"privateIP"`
		Ports        []portMapping `json:"ports"`
		HealthStatus string        `json:"healthStatus"`
		*Alias
	}{
		Alias: (*Alias)(m),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	m.state = aux.State
	m.privateIP = aux.PrivateIP
	if aux.Ports != nil {
		m.ports = aux.Ports
	} else {
		m.ports = []portMapping{}
	}
	m.healthStatus = aux.HealthStatus

	return nil
}

type awsClient struct {
	ecs *ecs.ECS
	ec2 *ec2.EC2
	ssm *ssm.SSM
}

// DefaultTemplateRule The default template for the default rule.
const DefaultTemplateRule = "Host(`{{ normalize .Name }}`)"

var (
	_                    provider.Provider = (*Provider)(nil)
	existingTaskDefCache                   = cache.New(30*time.Minute, 5*time.Minute)
)

// SetDefaults sets the default values.
func (p *Provider) SetDefaults() {
	p.Clusters = []string{"default"}
	p.AutoDiscoverClusters = false
	p.HealthyTasksOnly = false
	p.ExposedByDefault = true
	p.RefreshSeconds = 15
	p.DefaultRule = DefaultTemplateRule
}

// Init the provider.
func (p *Provider) Init() error {
	defaultRuleTpl, err := provider.MakeDefaultRuleTemplate(p.DefaultRule, nil)
	if err != nil {
		return fmt.Errorf("error while parsing default rule: %w", err)
	}

	p.defaultRuleTpl = defaultRuleTpl
	return nil
}

func (p *Provider) createClient(logger log.Logger) (*awsClient, error) {
	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return nil, err
	}

	ec2meta := ec2metadata.New(sess)
	if p.Region == "" && ec2meta.Available() {
		logger.Infoln("No region provided, querying instance metadata endpoint...")
		identity, err := ec2meta.GetInstanceIdentityDocument()
		if err != nil {
			return nil, err
		}
		p.Region = identity.Region
	}

	cfg := &aws.Config{
		Credentials: credentials.NewChainCredentials(
			[]credentials.Provider{
				&credentials.StaticProvider{
					Value: credentials.Value{
						AccessKeyID:     p.AccessKeyID,
						SecretAccessKey: p.SecretAccessKey,
					},
				},
				&credentials.EnvProvider{},
				&credentials.SharedCredentialsProvider{},
				defaults.RemoteCredProvider(*(defaults.Config()), defaults.Handlers()),
			}),
	}

	// Set the region if it is defined by the user or resolved from the EC2 metadata.
	if p.Region != "" {
		cfg.Region = &p.Region
	}

	cfg.WithLogger(aws.LoggerFunc(func(args ...interface{}) {
		logger.Debug(args...)
	}))

	return &awsClient{
		ecs.New(sess, cfg),
		ec2.New(sess, cfg),
		ssm.New(sess, cfg),
	}, nil
}

// Provide configuration to traefik from ECS.
func (p *Provider) Provide(configurationChan chan<- dynamic.Message, pool *safe.Pool) error {
	pool.GoCtx(func(routineCtx context.Context) {
		ctxLog := log.With(routineCtx, log.Str(log.ProviderName, "ecs"))
		logger := log.FromContext(ctxLog)

		operation := func() error {
			awsClient, err := p.createClient(logger)
			if err != nil {
				return fmt.Errorf("unable to create AWS client: %w", err)
			}

			err = p.loadConfiguration(ctxLog, awsClient, configurationChan)
			if err != nil {
				return fmt.Errorf("failed to get ECS configuration: %w", err)
			}

			ticker := time.NewTicker(time.Second * time.Duration(p.RefreshSeconds))
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					err = p.loadConfiguration(ctxLog, awsClient, configurationChan)
					if err != nil {
						return fmt.Errorf("failed to refresh ECS configuration: %w", err)
					}

				case <-routineCtx.Done():
					return nil
				}
			}
		}

		notify := func(err error, time time.Duration) {
			logger.Errorf("Provider connection error %+v, retrying in %s", err, time)
		}
		err := backoff.RetryNotify(safe.OperationWithRecover(operation), backoff.WithContext(job.NewBackOff(backoff.NewExponentialBackOff()), routineCtx), notify)
		if err != nil {
			logger.Errorf("Cannot connect to Provider api %+v", err)
		}
	})

	return nil
}

func (p *Provider) loadConfiguration(ctx context.Context, client *awsClient, configurationChan chan<- dynamic.Message) error {
	logger := log.FromContext(ctx)

	instances, err := p.listInstances(ctx, client)
	if err != nil {
		fmt.Errorf("unable to get configuration from ECS: %w", err)
	}
	
	if instances != nil {
		logger.Debugf("using configuration from ECS service discovery")
		configurationChan <- dynamic.Message{
			ProviderName:  "ecs",
			Configuration: p.buildConfiguration(ctx, instances),
		}

		logger.Debugf("writing to disk cache")
		if err := p.writeCacheFile(instances); err != nil {
			fmt.Errorf("writing cache file: %w", err)
		}
	} else {
		logger.Debugf("reading from disk cache")
		cachedInstances, err := p.readCacheFile()
		if err != nil {
			return fmt.Errorf("reading cache file: %w", err)
		}
		logger.Debugf("using cached ECS configuration from disk")
		configurationChan <- dynamic.Message{
			ProviderName:  "ecs",
			Configuration: p.buildConfiguration(ctx, cachedInstances),
		}
	}

	return nil
}

// Find all running Provider tasks in a cluster, also collect the task definitions (for docker labels)
// and the EC2 instance data.
func (p *Provider) listInstances(ctx context.Context, client *awsClient) ([]ecsInstance, error) {
	logger := log.FromContext(ctx)

	var clustersArn []*string
	var clusters []string

	if p.AutoDiscoverClusters {
		input := &ecs.ListClustersInput{}
		for {
			result, err := client.ecs.ListClusters(input)
			if err != nil {
				return nil, err
			}
			if result != nil {
				clustersArn = append(clustersArn, result.ClusterArns...)
				input.NextToken = result.NextToken
				if result.NextToken == nil {
					break
				}
			} else {
				break
			}
		}
		for _, cArn := range clustersArn {
			clusters = append(clusters, *cArn)
		}
	} else {
		clusters = p.Clusters
	}

	var instances []ecsInstance

	logger.Debugf("ECS Clusters: %s", clusters)
	for _, c := range clusters {
		input := &ecs.ListTasksInput{
			Cluster:       &c,
			DesiredStatus: aws.String(ecs.DesiredStatusRunning),
		}

		tasks := make(map[string]*ecs.Task)
		err := client.ecs.ListTasksPagesWithContext(ctx, input, func(page *ecs.ListTasksOutput, lastPage bool) bool {
			if len(page.TaskArns) > 0 {
				resp, err := client.ecs.DescribeTasksWithContext(ctx, &ecs.DescribeTasksInput{
					Tasks:   page.TaskArns,
					Cluster: &c,
				})
				if err != nil {
					logger.Errorf("Unable to describe tasks for %v", page.TaskArns)
				} else {
					for _, t := range resp.Tasks {
						if p.HealthyTasksOnly && aws.StringValue(t.HealthStatus) != ecs.HealthStatusHealthy {
							logger.Debugf("Skipping unhealthy task %s", aws.StringValue(t.TaskArn))
							continue
						}

						tasks[aws.StringValue(t.TaskArn)] = t
					}
				}
			}
			return !lastPage
		})
		if err != nil {
			return nil, fmt.Errorf("listing tasks: %w", err)
		}

		// Skip to the next cluster if there are no tasks found on
		// this cluster.
		if len(tasks) == 0 {
			continue
		}

		ec2Instances, err := p.lookupEc2Instances(ctx, client, &c, tasks)
		if err != nil {
			return nil, err
		}

		miInstances := make(map[string]*ssm.InstanceInformation)
		if p.ECSAnywhere {
			// Try looking up for instances on ECS Anywhere
			miInstances, err = p.lookupMiInstances(ctx, client, &c, tasks)
			if err != nil {
				return nil, err
			}
		}

		taskDefinitions, err := p.lookupTaskDefinitions(ctx, client, tasks)
		if err != nil {
			return nil, err
		}

		for key, task := range tasks {
			containerInstance := ec2Instances[aws.StringValue(task.ContainerInstanceArn)]
			taskDef := taskDefinitions[key]

			for _, container := range task.Containers {
				var containerDefinition *ecs.ContainerDefinition
				for _, def := range taskDef.ContainerDefinitions {
					if aws.StringValue(container.Name) == aws.StringValue(def.Name) {
						containerDefinition = def
						break
					}
				}

				if containerDefinition == nil {
					logger.Debugf("Unable to find container definition for %s", aws.StringValue(container.Name))
					continue
				}

				var mach *machine
				if len(task.Attachments) != 0 {
					var ports []portMapping
					for _, mapping := range containerDefinition.PortMappings {
						if mapping != nil {
							protocol := "TCP"
							if aws.StringValue(mapping.Protocol) == "udp" {
								protocol = "UDP"
							}

							ports = append(ports, portMapping{
								hostPort:      aws.Int64Value(mapping.HostPort),
								containerPort: aws.Int64Value(mapping.ContainerPort),
								protocol:      protocol,
							})
						}
					}
					mach = &machine{
						privateIP:    aws.StringValue(container.NetworkInterfaces[0].PrivateIpv4Address),
						ports:        ports,
						state:        aws.StringValue(task.LastStatus),
						healthStatus: aws.StringValue(task.HealthStatus),
					}
				} else {
					miContainerInstance := miInstances[aws.StringValue(task.ContainerInstanceArn)]
					if containerInstance == nil && miContainerInstance == nil {
						logger.Errorf("Unable to find container instance information for %s", aws.StringValue(container.Name))
						continue
					}

					var ports []portMapping
					for _, mapping := range container.NetworkBindings {
						if mapping != nil {
							ports = append(ports, portMapping{
								hostPort:      aws.Int64Value(mapping.HostPort),
								containerPort: aws.Int64Value(mapping.ContainerPort),
							})
						}
					}
					var privateIPAddress, stateName string
					if containerInstance != nil {
						privateIPAddress = aws.StringValue(containerInstance.PrivateIpAddress)
						stateName = aws.StringValue(containerInstance.State.Name)
					} else if miContainerInstance != nil {
						privateIPAddress = aws.StringValue(miContainerInstance.IPAddress)
						stateName = aws.StringValue(task.LastStatus)
					}

					mach = &machine{
						privateIP: privateIPAddress,
						ports:     ports,
						state:     stateName,
					}
				}

				instance := ecsInstance{
					Name:                fmt.Sprintf("%s-%s", strings.Replace(aws.StringValue(task.Group), ":", "-", 1), *container.Name),
					ID:                  key[len(key)-12:],
					containerDefinition: containerDefinition,
					machine:             mach,
					Labels:              aws.StringValueMap(containerDefinition.DockerLabels),
				}

				extraConf, err := p.getConfiguration(instance)
				if err != nil {
					log.FromContext(ctx).Errorf("Skip container %s: %w", getServiceName(instance), err)
					continue
				}
				instance.ExtraConf = extraConf

				instances = append(instances, instance)
			}
		}
	}

	return instances, nil
}

func (p *Provider) lookupMiInstances(ctx context.Context, client *awsClient, clusterName *string, ecsDatas map[string]*ecs.Task) (map[string]*ssm.InstanceInformation, error) {
	instanceIds := make(map[string]string)
	miInstances := make(map[string]*ssm.InstanceInformation)

	var containerInstancesArns []*string
	var instanceArns []*string

	for _, task := range ecsDatas {
		if task.ContainerInstanceArn != nil {
			containerInstancesArns = append(containerInstancesArns, task.ContainerInstanceArn)
		}
	}

	for _, arns := range p.chunkIDs(containerInstancesArns) {
		resp, err := client.ecs.DescribeContainerInstancesWithContext(ctx, &ecs.DescribeContainerInstancesInput{
			ContainerInstances: arns,
			Cluster:            clusterName,
		})
		if err != nil {
			return nil, fmt.Errorf("describing container instances: %w", err)
		}

		for _, container := range resp.ContainerInstances {
			instanceIds[aws.StringValue(container.Ec2InstanceId)] = aws.StringValue(container.ContainerInstanceArn)

			// Disallow EC2 Instance IDs
			// This prevents considering EC2 instances in ECS
			// and getting InvalidInstanceID.Malformed error when calling the describe-instances endpoint.
			if !strings.HasPrefix(aws.StringValue(container.Ec2InstanceId), "mi-") {
				continue
			}

			instanceArns = append(instanceArns, container.Ec2InstanceId)
		}
	}

	if len(instanceArns) > 0 {
		for _, ids := range p.chunkIDs(instanceArns) {
			input := &ssm.DescribeInstanceInformationInput{
				Filters: []*ssm.InstanceInformationStringFilter{
					{
						Key:    aws.String("InstanceIds"),
						Values: ids,
					},
				},
			}

			err := client.ssm.DescribeInstanceInformationPagesWithContext(ctx, input, func(page *ssm.DescribeInstanceInformationOutput, lastPage bool) bool {
				if len(page.InstanceInformationList) > 0 {
					for _, i := range page.InstanceInformationList {
						if i.InstanceId != nil {
							miInstances[instanceIds[aws.StringValue(i.InstanceId)]] = i
						}
					}
				}
				return !lastPage
			})
			if err != nil {
				return nil, fmt.Errorf("describing instances: %w", err)
			}
		}
	}

	return miInstances, nil
}

func (p *Provider) lookupEc2Instances(ctx context.Context, client *awsClient, clusterName *string, ecsDatas map[string]*ecs.Task) (map[string]*ec2.Instance, error) {
	instanceIds := make(map[string]string)
	ec2Instances := make(map[string]*ec2.Instance)

	var containerInstancesArns []*string
	var instanceArns []*string

	for _, task := range ecsDatas {
		if task.ContainerInstanceArn != nil {
			containerInstancesArns = append(containerInstancesArns, task.ContainerInstanceArn)
		}
	}

	for _, arns := range p.chunkIDs(containerInstancesArns) {
		resp, err := client.ecs.DescribeContainerInstancesWithContext(ctx, &ecs.DescribeContainerInstancesInput{
			ContainerInstances: arns,
			Cluster:            clusterName,
		})
		if err != nil {
			return nil, fmt.Errorf("describing container instances: %w", err)
		}

		for _, container := range resp.ContainerInstances {
			instanceIds[aws.StringValue(container.Ec2InstanceId)] = aws.StringValue(container.ContainerInstanceArn)
			// Disallow Instance IDs of the form mi-*
			// This prevents considering external instances in ECS Anywhere setups
			// and getting InvalidInstanceID.Malformed error when calling the describe-instances endpoint.
			if strings.HasPrefix(aws.StringValue(container.Ec2InstanceId), "mi-") {
				continue
			}

			instanceArns = append(instanceArns, container.Ec2InstanceId)
		}
	}

	if len(instanceArns) > 0 {
		for _, ids := range p.chunkIDs(instanceArns) {
			input := &ec2.DescribeInstancesInput{
				InstanceIds: ids,
			}

			err := client.ec2.DescribeInstancesPagesWithContext(ctx, input, func(page *ec2.DescribeInstancesOutput, lastPage bool) bool {
				if len(page.Reservations) > 0 {
					for _, r := range page.Reservations {
						for _, i := range r.Instances {
							if i.InstanceId != nil {
								ec2Instances[instanceIds[aws.StringValue(i.InstanceId)]] = i
							}
						}
					}
				}
				return !lastPage
			})
			if err != nil {
				return nil, fmt.Errorf("describing instances: %w", err)
			}
		}
	}

	return ec2Instances, nil
}

func (p *Provider) lookupTaskDefinitions(ctx context.Context, client *awsClient, taskDefArns map[string]*ecs.Task) (map[string]*ecs.TaskDefinition, error) {
	logger := log.FromContext(ctx)
	taskDef := make(map[string]*ecs.TaskDefinition)

	for arn, task := range taskDefArns {
		if definition, ok := existingTaskDefCache.Get(arn); ok {
			taskDef[arn] = definition.(*ecs.TaskDefinition)
			logger.Debugf("Found cached task definition for %s. Skipping the call", arn)
		} else {
			resp, err := client.ecs.DescribeTaskDefinitionWithContext(ctx, &ecs.DescribeTaskDefinitionInput{
				TaskDefinition: task.TaskDefinitionArn,
			})
			if err != nil {
				return nil, fmt.Errorf("describing task definition: %w", err)
			}

			taskDef[arn] = resp.TaskDefinition
			existingTaskDefCache.Set(arn, resp.TaskDefinition, cache.DefaultExpiration)
		}
	}
	return taskDef, nil
}

// chunkIDs ECS expects no more than 100 parameters be passed to a API call;
// thus, pack each string into an array capped at 100 elements.
func (p *Provider) chunkIDs(ids []*string) [][]*string {
	var chunked [][]*string
	for i := 0; i < len(ids); i += 100 {
		var sliceEnd int
		if i+100 < len(ids) {
			sliceEnd = i + 100
		} else {
			sliceEnd = len(ids)
		}
		chunked = append(chunked, ids[i:sliceEnd])
	}
	return chunked
}

func (p *Provider) readCacheFile() ([]ecsInstance, error) {
	filePath := "/tmp/traefik/ecs.cache.json"

	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening cache file: %w", err)
	}
	defer f.Close()

	content, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("error reading cache file: %w", err)
	}

	var instances []ecsInstance
	err = json.Unmarshal(content, &instances)
	if err != nil {
		return nil, fmt.Errorf("error decoding cache file: %w", err)
	}

	return instances, nil
}

func (p *Provider) writeCacheFile(instances []ecsInstance) error {
	filePath := "/tmp/traefik/ecs.cache.json"
	fileLock := flock.New(filePath + ".lock")

	locked, err := fileLock.TryLock()
	if err != nil {
		return fmt.Errorf("lock not possible on cache file: %w", err)
	}

	if locked {
		defer fileLock.Unlock()
			
		jsonData, err := json.Marshal(instances)
		if err != nil {
			return fmt.Errorf("error marshalling json cache: %w", err)
		}

		file, err := os.Create(filePath)
		if err != nil {
			return fmt.Errorf("Error creating file:", err)
		}
		defer file.Close()

		_, err = file.Write(jsonData)
		if err != nil {
			return fmt.Errorf("Error writing JSON data to file:", err)
		}
	}

	return nil
}