// ShieldOps Azure Bicep Template
// Deploys: AKS, PostgreSQL, Redis, Event Hubs, ACR, App Gateway (WAF),
//          Key Vault, Log Analytics, VNet, Front Door
// Usage: az deployment group create -g shieldops-rg -f main.bicep -p main.bicepparam

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------
@description('Azure region for all resources')
param location string = resourceGroup().location

@description('Environment name')
@allowed(['dev', 'staging', 'production'])
param environment string = 'production'

@description('Custom domain for ShieldOps')
param domainName string = 'shieldops.example.com'

@description('PostgreSQL administrator password')
@secure()
param postgresAdminPassword string

@description('SSH public key for AKS nodes')
param aksSSHPublicKey string = ''

@description('AAD admin object ID for Key Vault access')
param adminObjectId string

// ---------------------------------------------------------------------------
// Variables
// ---------------------------------------------------------------------------
var prefix = 'shieldops'
var tags = {
  app: 'shieldops'
  environment: environment
  managedBy: 'bicep'
}

// Networking
var vnetAddressPrefix = '10.0.0.0/16'
var aksSubnetPrefix = '10.0.0.0/20'
var dbSubnetPrefix = '10.0.16.0/24'
var redisSubnetPrefix = '10.0.17.0/24'
var appGwSubnetPrefix = '10.0.18.0/24'

// ---------------------------------------------------------------------------
// 1. Virtual Network + Subnets
// ---------------------------------------------------------------------------
resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: '${prefix}-vnet'
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [vnetAddressPrefix]
    }
    subnets: [
      {
        name: 'aks-subnet'
        properties: {
          addressPrefix: aksSubnetPrefix
          privateEndpointNetworkPolicies: 'Disabled'
          serviceEndpoints: [
            { service: 'Microsoft.Sql' }
            { service: 'Microsoft.KeyVault' }
          ]
        }
      }
      {
        name: 'db-subnet'
        properties: {
          addressPrefix: dbSubnetPrefix
          delegations: [
            {
              name: 'postgresql-delegation'
              properties: {
                serviceName: 'Microsoft.DBforPostgreSQL/flexibleServers'
              }
            }
          ]
        }
      }
      {
        name: 'redis-subnet'
        properties: {
          addressPrefix: redisSubnetPrefix
        }
      }
      {
        name: 'appgw-subnet'
        properties: {
          addressPrefix: appGwSubnetPrefix
        }
      }
    ]
  }
}

// ---------------------------------------------------------------------------
// 2. AKS Cluster (managed identity, 3 nodes, Standard_D4s_v3)
// ---------------------------------------------------------------------------
resource aksIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${prefix}-aks-identity'
  location: location
  tags: tags
}

resource aks 'Microsoft.ContainerService/managedClusters@2024-01-01' = {
  name: '${prefix}-aks'
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${aksIdentity.id}': {}
    }
  }
  properties: {
    dnsPrefix: '${prefix}-aks'
    kubernetesVersion: '1.29'
    networkProfile: {
      networkPlugin: 'azure'
      networkPolicy: 'calico'
      serviceCidr: '10.1.0.0/16'
      dnsServiceIP: '10.1.0.10'
      loadBalancerSku: 'standard'
    }
    agentPoolProfiles: [
      {
        name: 'system'
        count: 3
        vmSize: 'Standard_D4s_v3'
        osType: 'Linux'
        osSKU: 'AzureLinux'
        mode: 'System'
        vnetSubnetID: vnet.properties.subnets[0].id
        enableAutoScaling: true
        minCount: 2
        maxCount: 6
        maxPods: 110
        availabilityZones: ['1', '2', '3']
        osDiskSizeGB: 128
        osDiskType: 'Managed'
      }
    ]
    addonProfiles: {
      omsagent: {
        enabled: true
        config: {
          logAnalyticsWorkspaceResourceID: logAnalytics.id
        }
      }
      azureKeyvaultSecretsProvider: {
        enabled: true
      }
    }
    autoUpgradeProfile: {
      upgradeChannel: 'stable'
    }
    linuxProfile: aksSSHPublicKey != '' ? {
      adminUsername: 'azureuser'
      ssh: {
        publicKeys: [
          {
            keyData: aksSSHPublicKey
          }
        ]
      }
    } : null
    enableRBAC: true
    aadProfile: {
      managed: true
      enableAzureRBAC: true
    }
  }
}

// ---------------------------------------------------------------------------
// 3. Azure Database for PostgreSQL Flexible Server (HA)
// ---------------------------------------------------------------------------
resource privateDnsZonePg 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: '${prefix}.private.postgres.database.azure.com'
  location: 'global'
  tags: tags
}

resource privateDnsZonePgLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: privateDnsZonePg
  name: '${prefix}-pg-vnet-link'
  location: 'global'
  properties: {
    virtualNetwork: {
      id: vnet.id
    }
    registrationEnabled: false
  }
}

resource postgres 'Microsoft.DBforPostgreSQL/flexibleServers@2023-12-01-preview' = {
  name: '${prefix}-pg'
  location: location
  tags: tags
  sku: {
    name: 'Standard_D4s_v3'
    tier: 'GeneralPurpose'
  }
  properties: {
    version: '15'
    administratorLogin: 'shieldops_admin'
    administratorLoginPassword: postgresAdminPassword
    storage: {
      storageSizeGB: 128
      autoGrow: 'Enabled'
    }
    backup: {
      backupRetentionDays: 35
      geoRedundantBackup: 'Enabled'
    }
    highAvailability: {
      mode: 'ZoneRedundant'
    }
    network: {
      delegatedSubnetResourceId: vnet.properties.subnets[1].id
      privateDnsZoneArmResourceId: privateDnsZonePg.id
    }
    maintenanceWindow: {
      customWindow: 'Enabled'
      dayOfWeek: 0
      startHour: 3
      startMinute: 0
    }
  }
  dependsOn: [privateDnsZonePgLink]
}

resource postgresDb 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2023-12-01-preview' = {
  parent: postgres
  name: 'shieldops'
  properties: {
    charset: 'UTF8'
    collation: 'en_US.utf8'
  }
}

// ---------------------------------------------------------------------------
// 4. Azure Cache for Redis (Premium P1)
// ---------------------------------------------------------------------------
resource redis 'Microsoft.Cache/redis@2023-08-01' = {
  name: '${prefix}-redis'
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'Premium'
      family: 'P'
      capacity: 1
    }
    enableNonSslPort: false
    minimumTlsVersion: '1.2'
    redisVersion: '7'
    subnetId: vnet.properties.subnets[2].id
    redisConfiguration: {
      'maxmemory-policy': 'allkeys-lru'
      'maxmemory-reserved': '256'
    }
    replicasPerMaster: 1
  }
}

// ---------------------------------------------------------------------------
// 5. Azure Event Hubs (Kafka-compatible)
// ---------------------------------------------------------------------------
resource eventHubNamespace 'Microsoft.EventHub/namespaces@2024-01-01' = {
  name: '${prefix}-eventhub'
  location: location
  tags: tags
  sku: {
    name: 'Standard'
    tier: 'Standard'
    capacity: 2
  }
  properties: {
    kafkaEnabled: true
    isAutoInflateEnabled: true
    maximumThroughputUnits: 10
    minimumTlsVersion: '1.2'
  }
}

resource eventHubAgentEvents 'Microsoft.EventHub/namespaces/eventhubs@2024-01-01' = {
  parent: eventHubNamespace
  name: 'agent-events'
  properties: {
    partitionCount: 8
    messageRetentionInDays: 7
  }
}

resource eventHubSecurityAlerts 'Microsoft.EventHub/namespaces/eventhubs@2024-01-01' = {
  parent: eventHubNamespace
  name: 'security-alerts'
  properties: {
    partitionCount: 4
    messageRetentionInDays: 7
  }
}

resource eventHubTelemetry 'Microsoft.EventHub/namespaces/eventhubs@2024-01-01' = {
  parent: eventHubNamespace
  name: 'telemetry'
  properties: {
    partitionCount: 8
    messageRetentionInDays: 3
  }
}

// ---------------------------------------------------------------------------
// 6. Azure Container Registry (Premium)
// ---------------------------------------------------------------------------
resource acr 'Microsoft.ContainerRegistry/registries@2023-11-01-preview' = {
  name: '${prefix}acr'
  location: location
  tags: tags
  sku: {
    name: 'Premium'
  }
  properties: {
    adminUserEnabled: false
    publicNetworkAccess: 'Enabled'
    networkRuleBypassOptions: 'AzureServices'
    policies: {
      retentionPolicy: {
        status: 'enabled'
        days: 30
      }
      trustPolicy: {
        type: 'Notary'
        status: 'enabled'
      }
    }
    encryption: {
      status: 'disabled'
    }
  }
}

// Grant AKS pull access to ACR
resource acrPullRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, aksIdentity.id, 'acrpull')
  scope: acr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
    principalId: aksIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// ---------------------------------------------------------------------------
// 7. Key Vault
// ---------------------------------------------------------------------------
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: '${prefix}-kv'
  location: location
  tags: tags
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
      virtualNetworkRules: [
        {
          id: vnet.properties.subnets[0].id
        }
      ]
    }
  }
}

// Admin access policy
resource kvAdminRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, adminObjectId, 'kv-admin')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '00482a5a-887f-4fb3-b363-3b7fe8e74483')
    principalId: adminObjectId
    principalType: 'User'
  }
}

// AKS secrets access
resource kvAksRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, aksIdentity.id, 'kv-secrets')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
    principalId: aksIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Store secrets
var secretNames = [
  'anthropic-api-key'
  'openai-api-key'
  'jwt-secret'
  'stripe-secret-key'
  'stripe-webhook-secret'
  'slack-bot-token'
  'pagerduty-api-key'
  'langsmith-api-key'
  'opa-endpoint'
]

resource kvSecrets 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = [for name in secretNames: {
  parent: keyVault
  name: name
  properties: {
    value: 'REPLACE_ME'
    attributes: {
      enabled: true
    }
  }
}]

resource kvPostgresPassword 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'postgres-admin-password'
  properties: {
    value: postgresAdminPassword
    attributes: {
      enabled: true
    }
  }
}

// ---------------------------------------------------------------------------
// 8. Log Analytics Workspace + Azure Monitor
// ---------------------------------------------------------------------------
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${prefix}-logs'
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 90
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
    workspaceCapping: {
      dailyQuotaGb: 10
    }
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: '${prefix}-appinsights'
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalytics.id
    RetentionInDays: 90
    IngestionMode: 'LogAnalytics'
  }
}

// Alert: High CPU on AKS
resource alertCpu 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: '${prefix}-aks-high-cpu'
  location: 'global'
  tags: tags
  properties: {
    severity: 2
    enabled: true
    scopes: [aks.id]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'cpu-usage'
          metricName: 'node_cpu_usage_percentage'
          metricNamespace: 'Microsoft.ContainerService/managedClusters'
          operator: 'GreaterThan'
          threshold: 80
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    autoMitigate: true
  }
}

// Alert: High Memory on AKS
resource alertMemory 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: '${prefix}-aks-high-memory'
  location: 'global'
  tags: tags
  properties: {
    severity: 2
    enabled: true
    scopes: [aks.id]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'memory-usage'
          metricName: 'node_memory_working_set_percentage'
          metricNamespace: 'Microsoft.ContainerService/managedClusters'
          operator: 'GreaterThan'
          threshold: 80
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    autoMitigate: true
  }
}

// Alert: PostgreSQL high CPU
resource alertPgCpu 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: '${prefix}-pg-high-cpu'
  location: 'global'
  tags: tags
  properties: {
    severity: 2
    enabled: true
    scopes: [postgres.id]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'pg-cpu'
          metricName: 'cpu_percent'
          metricNamespace: 'Microsoft.DBforPostgreSQL/flexibleServers'
          operator: 'GreaterThan'
          threshold: 85
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    autoMitigate: true
  }
}

// ---------------------------------------------------------------------------
// 9. Application Gateway v2 (WAF)
// ---------------------------------------------------------------------------
resource appGwPublicIp 'Microsoft.Network/publicIPAddresses@2023-11-01' = {
  name: '${prefix}-appgw-pip'
  location: location
  tags: tags
  sku: {
    name: 'Standard'
    tier: 'Regional'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    dnsSettings: {
      domainNameLabel: prefix
    }
  }
}

resource wafPolicy 'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies@2023-11-01' = {
  name: '${prefix}-waf-policy'
  location: location
  tags: tags
  properties: {
    policySettings: {
      requestBodyCheck: true
      maxRequestBodySizeInKb: 128
      fileUploadLimitInMb: 100
      state: 'Enabled'
      mode: 'Prevention'
    }
    managedRules: {
      managedRuleSets: [
        {
          ruleSetType: 'OWASP'
          ruleSetVersion: '3.2'
        }
        {
          ruleSetType: 'Microsoft_BotManagerRuleSet'
          ruleSetVersion: '1.0'
        }
      ]
    }
    customRules: [
      {
        name: 'RateLimitPerIP'
        priority: 100
        ruleType: 'RateLimitRule'
        rateLimitDuration: 'OneMin'
        rateLimitThreshold: 100
        matchConditions: [
          {
            matchVariables: [
              {
                variableName: 'RemoteAddr'
              }
            ]
            operator: 'IPMatch'
            negationConditon: true
            matchValues: ['10.0.0.0/8']
          }
        ]
        action: 'Block'
        groupByUserSession: [
          {
            groupByVariables: [
              {
                variableName: 'ClientAddr'
              }
            ]
          }
        ]
      }
    ]
  }
}

resource appGw 'Microsoft.Network/applicationGateways@2023-11-01' = {
  name: '${prefix}-appgw'
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'WAF_v2'
      tier: 'WAF_v2'
      capacity: 2
    }
    gatewayIPConfigurations: [
      {
        name: 'gateway-ip-config'
        properties: {
          subnet: {
            id: vnet.properties.subnets[3].id
          }
        }
      }
    ]
    frontendIPConfigurations: [
      {
        name: 'frontend-ip'
        properties: {
          publicIPAddress: {
            id: appGwPublicIp.id
          }
        }
      }
    ]
    frontendPorts: [
      {
        name: 'port-80'
        properties: {
          port: 80
        }
      }
      {
        name: 'port-443'
        properties: {
          port: 443
        }
      }
    ]
    backendAddressPools: [
      {
        name: 'shieldops-backend'
        properties: {
          backendAddresses: []
        }
      }
    ]
    backendHttpSettingsCollection: [
      {
        name: 'http-settings'
        properties: {
          port: 8000
          protocol: 'Http'
          cookieBasedAffinity: 'Disabled'
          requestTimeout: 30
          probe: {
            id: resourceId('Microsoft.Network/applicationGateways/probes', '${prefix}-appgw', 'health-probe')
          }
        }
      }
    ]
    httpListeners: [
      {
        name: 'http-listener'
        properties: {
          frontendIPConfiguration: {
            id: resourceId('Microsoft.Network/applicationGateways/frontendIPConfigurations', '${prefix}-appgw', 'frontend-ip')
          }
          frontendPort: {
            id: resourceId('Microsoft.Network/applicationGateways/frontendPorts', '${prefix}-appgw', 'port-80')
          }
          protocol: 'Http'
        }
      }
    ]
    redirectConfigurations: [
      {
        name: 'http-to-https'
        properties: {
          redirectType: 'Permanent'
          targetListener: {
            id: resourceId('Microsoft.Network/applicationGateways/httpListeners', '${prefix}-appgw', 'http-listener')
          }
          includePath: true
          includeQueryString: true
        }
      }
    ]
    requestRoutingRules: [
      {
        name: 'default-rule'
        properties: {
          priority: 100
          ruleType: 'Basic'
          httpListener: {
            id: resourceId('Microsoft.Network/applicationGateways/httpListeners', '${prefix}-appgw', 'http-listener')
          }
          backendAddressPool: {
            id: resourceId('Microsoft.Network/applicationGateways/backendAddressPools', '${prefix}-appgw', 'shieldops-backend')
          }
          backendHttpSettings: {
            id: resourceId('Microsoft.Network/applicationGateways/backendHttpSettingsCollection', '${prefix}-appgw', 'http-settings')
          }
        }
      }
    ]
    probes: [
      {
        name: 'health-probe'
        properties: {
          protocol: 'Http'
          host: '127.0.0.1'
          port: 8000
          path: '/health'
          interval: 15
          timeout: 10
          unhealthyThreshold: 3
        }
      }
    ]
    firewallPolicy: {
      id: wafPolicy.id
    }
  }
}

// ---------------------------------------------------------------------------
// 10. Azure Front Door (CDN for dashboard)
// ---------------------------------------------------------------------------
resource frontDoorProfile 'Microsoft.Cdn/profiles@2023-07-01-preview' = {
  name: '${prefix}-fd'
  location: 'global'
  tags: tags
  sku: {
    name: 'Standard_AzureFrontDoor'
  }
}

resource frontDoorEndpoint 'Microsoft.Cdn/profiles/afdEndpoints@2023-07-01-preview' = {
  parent: frontDoorProfile
  name: '${prefix}-endpoint'
  location: 'global'
  tags: tags
  properties: {
    enabledState: 'Enabled'
  }
}

resource frontDoorOriginGroup 'Microsoft.Cdn/profiles/originGroups@2023-07-01-preview' = {
  parent: frontDoorProfile
  name: 'shieldops-origin-group'
  properties: {
    loadBalancingSettings: {
      sampleSize: 4
      successfulSamplesRequired: 3
      additionalLatencyInMilliseconds: 50
    }
    healthProbeSettings: {
      probePath: '/health'
      probeRequestType: 'HEAD'
      probeProtocol: 'Http'
      probeIntervalInSeconds: 30
    }
    sessionAffinityState: 'Disabled'
  }
}

resource frontDoorOrigin 'Microsoft.Cdn/profiles/originGroups/origins@2023-07-01-preview' = {
  parent: frontDoorOriginGroup
  name: 'appgw-origin'
  properties: {
    hostName: appGwPublicIp.properties.dnsSettings.fqdn
    httpPort: 80
    httpsPort: 443
    priority: 1
    weight: 1000
    enabledState: 'Enabled'
  }
}

resource frontDoorRoute 'Microsoft.Cdn/profiles/afdEndpoints/routes@2023-07-01-preview' = {
  parent: frontDoorEndpoint
  name: 'default-route'
  properties: {
    originGroup: {
      id: frontDoorOriginGroup.id
    }
    supportedProtocols: ['Http', 'Https']
    patternsToMatch: ['/*']
    forwardingProtocol: 'HttpOnly'
    linkToDefaultDomain: 'Enabled'
    httpsRedirect: 'Enabled'
    enabledState: 'Enabled'
  }
  dependsOn: [frontDoorOrigin]
}

// ---------------------------------------------------------------------------
// Outputs
// ---------------------------------------------------------------------------
output aksClusterName string = aks.name
output aksClusterFqdn string = aks.properties.fqdn
output postgresServerName string = postgres.name
output postgresFqdn string = postgres.properties.fullyQualifiedDomainName
output redisHostName string = redis.properties.hostName
output eventHubNamespace string = eventHubNamespace.name
output acrLoginServer string = acr.properties.loginServer
output keyVaultName string = keyVault.name
output keyVaultUri string = keyVault.properties.vaultUri
output logAnalyticsWorkspaceId string = logAnalytics.properties.customerId
output appGatewayPublicIp string = appGwPublicIp.properties.ipAddress
output frontDoorEndpointHostname string = frontDoorEndpoint.properties.hostName
output appInsightsInstrumentationKey string = appInsights.properties.InstrumentationKey
output appInsightsConnectionString string = appInsights.properties.ConnectionString
