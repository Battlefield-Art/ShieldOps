import { BrowserRouter, Routes, Route, Navigate, useSearchParams } from "react-router-dom";
import { lazy, Suspense, useEffect, useState } from "react";
import Layout from "./components/Layout";
import LandingLayout from "./components/landing/LandingLayout";
import LoadingSpinner from "./components/LoadingSpinner";
import { useAuthStore } from "./store/auth";
import { isDemoMode } from "./demo/config";
import { loginAsDemo } from "./demo/demoAuth";

// ── Eagerly loaded (critical path) ─────────────────────────────────
import Landing from "./pages/Landing";
import Login from "./pages/Login";
import AgentFactory from "./pages/AgentFactory";

import NotFound from "./pages/NotFound";

// ── Lazy-loaded pages ──────────────────────────────────────────────
const ProductLanding = lazy(() => import("./pages/ProductLanding"));
const Pricing = lazy(() => import("./pages/Pricing"));
const SEOIndex = lazy(() => import("./pages/SEOIndex"));
const SEOPage = lazy(() => import("./pages/SEOPage"));
const AgentTask = lazy(() => import("./pages/AgentTask"));
const AgentHistory = lazy(() => import("./pages/AgentHistory"));
const WarRoom = lazy(() => import("./pages/WarRoom"));
const FleetOverview = lazy(() => import("./pages/FleetOverview"));
const Investigations = lazy(() => import("./pages/Investigations"));
const InvestigationDetail = lazy(() => import("./pages/InvestigationDetail"));
const Remediations = lazy(() => import("./pages/Remediations"));
const RemediationDetail = lazy(() => import("./pages/RemediationDetail"));
const Security = lazy(() => import("./pages/Security"));
const Cost = lazy(() => import("./pages/Cost"));
const Learning = lazy(() => import("./pages/Learning"));
const Analytics = lazy(() => import("./pages/Analytics"));
const AgentPerformance = lazy(() => import("./pages/AgentPerformance"));
const Settings = lazy(() => import("./pages/Settings"));
const VulnerabilityList = lazy(() => import("./pages/VulnerabilityList"));
const VulnerabilityDetailPage = lazy(() => import("./pages/VulnerabilityDetail"));
const AuditLog = lazy(() => import("./pages/AuditLog"));
const Playbooks = lazy(() => import("./pages/Playbooks"));
const PlaybookEditor = lazy(() => import("./pages/PlaybookEditor"));
const UserManagement = lazy(() => import("./pages/UserManagement"));
const IncidentTimeline = lazy(() => import("./pages/IncidentTimeline"));
const Billing = lazy(() => import("./pages/Billing"));
const SystemHealth = lazy(() => import("./pages/SystemHealth"));
const OnboardingWizard = lazy(() => import("./pages/OnboardingWizard"));
const Marketplace = lazy(() => import("./pages/Marketplace"));
const IncidentCorrelation = lazy(() => import("./pages/IncidentCorrelation"));
const ComplianceDashboard = lazy(() => import("./pages/ComplianceDashboard"));
const Predictions = lazy(() => import("./pages/Predictions"));
const CapacityForecast = lazy(() => import("./pages/CapacityForecast"));
const InfraAsCode = lazy(() => import("./pages/InfraAsCode"));
const PipelineRuns = lazy(() => import("./pages/PipelineRuns"));
const APIKeys = lazy(() => import("./pages/APIKeys"));
const Workflows = lazy(() => import("./pages/Workflows"));
const ScheduledTasks = lazy(() => import("./pages/ScheduledTasks"));
const MCPServers = lazy(() => import("./pages/MCPServers"));
const ChatOps = lazy(() => import("./pages/ChatOps"));
const EnterpriseIntegrations = lazy(() => import("./pages/EnterpriseIntegrations"));
const AutomationRules = lazy(() => import("./pages/AutomationRules"));
const TelemetryOptimizer = lazy(() => import("./pages/TelemetryOptimizer"));
const RiskScoring = lazy(() => import("./pages/RiskScoring"));
const OTelPipeline = lazy(() => import("./pages/OTelPipeline"));
const ThreatIntel = lazy(() => import("./pages/ThreatIntel"));
const IncidentCommander = lazy(() => import("./pages/IncidentCommander"));
const ComplianceAudit = lazy(() => import("./pages/ComplianceAudit"));
const OTelCollectorManager = lazy(() => import("./pages/OTelCollectorManager"));
const AdaptiveSecurity = lazy(() => import("./pages/AdaptiveSecurity"));
const OTelDeployer = lazy(() => import("./pages/OTelDeployer"));
const SecurityPosture = lazy(() => import("./pages/SecurityPosture"));
const OTelSemantic = lazy(() => import("./pages/OTelSemantic"));
const SOARWorkflow = lazy(() => import("./pages/SOARWorkflow"));
const TailSampling = lazy(() => import("./pages/TailSampling"));
const DetectionEngineering = lazy(() => import("./pages/DetectionEngineering"));
const MetricsPipeline = lazy(() => import("./pages/MetricsPipeline"));
const SecurityTesting = lazy(() => import("./pages/SecurityTesting"));
const LogsPipeline = lazy(() => import("./pages/LogsPipeline"));
const ThreatModeling = lazy(() => import("./pages/ThreatModeling"));
const Situations = lazy(() => import("./pages/Situations"));
const SituationDetail = lazy(() => import("./pages/SituationDetail"));
const AgentFirewall = lazy(() => import("./pages/AgentFirewall"));
const NHIRegistry = lazy(() => import("./pages/NHIRegistry"));
const MCPSecurity = lazy(() => import("./pages/MCPSecurity"));
const DataPipelineSecurity = lazy(() => import("./pages/DataPipelineSecurity"));
const CredentialLifecycle = lazy(() => import("./pages/CredentialLifecycle"));
const VendorNormalizer = lazy(() => import("./pages/VendorNormalizer"));
const AttackCampaign = lazy(() => import("./pages/AttackCampaign"));
const SituationComposer = lazy(() => import("./pages/SituationComposer"));
const ComplianceReporter = lazy(() => import("./pages/ComplianceReporter"));
const OAuthAnalyzer = lazy(() => import("./pages/OAuthAnalyzer"));
const LateralMovement = lazy(() => import("./pages/LateralMovement"));
const ShadowAIDiscovery = lazy(() => import("./pages/ShadowAIDiscovery"));
const SecretsScanner = lazy(() => import("./pages/SecretsScanner"));
const APISecurity = lazy(() => import("./pages/APISecurity"));
const PolicyEngine = lazy(() => import("./pages/PolicyEngine"));
const CloudPosture = lazy(() => import("./pages/CloudPosture"));
const ContainerSecurity = lazy(() => import("./pages/ContainerSecurity"));
const SupplyChainSecurity = lazy(() => import("./pages/SupplyChainSecurity"));
const IncidentTriage = lazy(() => import("./pages/IncidentTriage"));
const ChangeRiskAnalyzer = lazy(() => import("./pages/ChangeRiskAnalyzer"));
const CostAnomaly = lazy(() => import("./pages/CostAnomaly"));
const AdversarialValidation = lazy(() => import("./pages/AdversarialValidation"));
const MCPGateway = lazy(() => import("./pages/MCPGateway"));
const ServiceAccountTracker = lazy(() => import("./pages/ServiceAccountTracker"));
const DataClassification = lazy(() => import("./pages/DataClassification"));
const AccessReview = lazy(() => import("./pages/AccessReview"));
const RunbookAutomation = lazy(() => import("./pages/RunbookAutomation"));
const CapacityPlanner = lazy(() => import("./pages/CapacityPlanner"));
const DisasterRecovery = lazy(() => import("./pages/DisasterRecovery"));
const LogAnalyzer = lazy(() => import("./pages/LogAnalyzer"));
const ChaosEngineering = lazy(() => import("./pages/ChaosEngineering"));
const SLAMonitor = lazy(() => import("./pages/SLAMonitor"));
const ConfigValidator = lazy(() => import("./pages/ConfigValidator"));
const NetworkSegmentation = lazy(() => import("./pages/NetworkSegmentation"));
const WorkflowEngine = lazy(() => import("./pages/WorkflowEngine"));
const AlertCorrelation = lazy(() => import("./pages/AlertCorrelation"));
const PerformanceProfiler = lazy(() => import("./pages/PerformanceProfiler"));
const AnomalyDetector = lazy(() => import("./pages/AnomalyDetector"));
const CertificateManager = lazy(() => import("./pages/CertificateManager"));
const DNSSecurity = lazy(() => import("./pages/DNSSecurity"));
const BackupValidator = lazy(() => import("./pages/BackupValidator"));
const VulnerabilityManager = lazy(() => import("./pages/VulnerabilityManager"));
const ComplianceScanner = lazy(() => import("./pages/ComplianceScanner"));
const ThreatResponse = lazy(() => import("./pages/ThreatResponse"));
const AgentGovernance = lazy(() => import("./pages/AgentGovernance"));
const ModelSecurity = lazy(() => import("./pages/ModelSecurity"));
const PromptShield = lazy(() => import("./pages/PromptShield"));
const MultiAgentSecurity = lazy(() => import("./pages/MultiAgentSecurity"));
const AICompliance = lazy(() => import("./pages/AICompliance"));
const DigitalTwinSecurity = lazy(() => import("./pages/DigitalTwinSecurity"));
const AgenticMDR = lazy(() => import("./pages/AgenticMDR"));
const BreakoutDefender = lazy(() => import("./pages/BreakoutDefender"));
const AITriageAccelerator = lazy(() => import("./pages/AITriageAccelerator"));
const SOCTransformation = lazy(() => import("./pages/SOCTransformation"));
const CloudRiskRanker = lazy(() => import("./pages/CloudRiskRanker"));
const DataLossPrevention = lazy(() => import("./pages/DataLossPrevention"));
const AutonomousXDR = lazy(() => import("./pages/AutonomousXDR"));
const AutonomousSOC = lazy(() => import("./pages/AutonomousSOC"));
const CNAPPAnalyzer = lazy(() => import("./pages/CNAPPAnalyzer"));
const ZeroTrustNetwork = lazy(() => import("./pages/ZeroTrustNetwork"));
const IntelligentSOAR = lazy(() => import("./pages/IntelligentSOAR"));
const MalwareAnalyzer = lazy(() => import("./pages/MalwareAnalyzer"));
const CyberRecovery = lazy(() => import("./pages/CyberRecovery"));
const DataThreatHunting = lazy(() => import("./pages/DataThreatHunting"));
const SensitiveDataMonitor = lazy(() => import("./pages/SensitiveDataMonitor"));
const IdentityProtection = lazy(() => import("./pages/IdentityProtection"));
const ExposureManagement = lazy(() => import("./pages/ExposureManagement"));
const AISOCAssistant = lazy(() => import("./pages/AISOCAssistant"));
const LogIntelligence = lazy(() => import("./pages/LogIntelligence"));
const InsiderThreat = lazy(() => import("./pages/InsiderThreat"));
const RansomwareForensics = lazy(() => import("./pages/RansomwareForensics"));
const ThreatIntelligencePlatform = lazy(() => import("./pages/ThreatIntelligencePlatform"));
const CodeSecurityScanner = lazy(() => import("./pages/CodeSecurityScanner"));
const DataResilience = lazy(() => import("./pages/DataResilience"));
const ManagedThreatHunting = lazy(() => import("./pages/ManagedThreatHunting"));
const VulnerabilityIntelligence = lazy(() => import("./pages/VulnerabilityIntelligence"));
const FileIntegrityMonitor = lazy(() => import("./pages/FileIntegrityMonitor"));
const IoTOTSecurity = lazy(() => import("./pages/IoTOTSecurity"));
const SecurityAppBuilder = lazy(() => import("./pages/SecurityAppBuilder"));
const AirGapVault = lazy(() => import("./pages/AirGapVault"));

const AgentMemoryStore = lazy(() => import("./pages/AgentMemoryStore"));
const ReflectionEngine = lazy(() => import("./pages/ReflectionEngine"));
const SupplyChainScanner = lazy(() => import("./pages/SupplyChainScanner"));
const CrossVendorCorrelator = lazy(() => import("./pages/CrossVendorCorrelator"));
const SituationManager = lazy(() => import("./pages/SituationManager"));
const TrustRelationshipMapper = lazy(() => import("./pages/TrustRelationshipMapper"));
const ITAssetIntelligence = lazy(() => import("./pages/ITAssetIntelligence"));
const AIRuntimeGuardian = lazy(() => import("./pages/AIRuntimeGuardian"));
const DataIntelligence = lazy(() => import("./pages/DataIntelligence"));
const EndpointDLP = lazy(() => import("./pages/EndpointDLP"));
const UnifiedCloudSecurity = lazy(() => import("./pages/UnifiedCloudSecurity"));
const BackupSecurityPosture = lazy(() => import("./pages/BackupSecurityPosture"));

const NetworkPentest = lazy(() => import("./pages/NetworkPentest"));
const WebAppScanner = lazy(() => import("./pages/WebAppScanner"));
const CloudPentest = lazy(() => import("./pages/CloudPentest"));
const APIPentest = lazy(() => import("./pages/APIPentest"));
const CredentialTester = lazy(() => import("./pages/CredentialTester"));
const PatchOrchestrator = lazy(() => import("./pages/PatchOrchestrator"));
const ConfigRemediation = lazy(() => import("./pages/ConfigRemediation"));
const AccessRemediation = lazy(() => import("./pages/AccessRemediation"));
const VulnerabilityRemediation = lazy(() => import("./pages/VulnerabilityRemediation"));
const RemediationVerifier = lazy(() => import("./pages/RemediationVerifier"));
const MITRECoverage = lazy(() => import("./pages/MITRECoverage"));
const DetectionGapFinder = lazy(() => import("./pages/DetectionGapFinder"));
const SecurityScorecard = lazy(() => import("./pages/SecurityScorecard"));
const ComplianceGapAnalyzer = lazy(() => import("./pages/ComplianceGapAnalyzer"));
const AttackReadiness = lazy(() => import("./pages/AttackReadiness"));
const SecurityPipeline2 = lazy(() => import("./pages/SecurityPipeline"));
const FindingCorrelator = lazy(() => import("./pages/FindingCorrelator"));
const AutoTicketManager = lazy(() => import("./pages/AutoTicketManager"));
const ContinuousScanner = lazy(() => import("./pages/ContinuousScanner"));
const RiskPrioritizer = lazy(() => import("./pages/RiskPrioritizer"));
const SecurityDashboardAggregator = lazy(() => import("./pages/SecurityDashboardAggregator"));
const ExecutiveReporter = lazy(() => import("./pages/ExecutiveReporter"));
const RemediationOrchestrator = lazy(() => import("./pages/RemediationOrchestrator"));
const PhishingSimulator = lazy(() => import("./pages/PhishingSimulator"));

// ── Suspense fallback ──────────────────────────────────────────────

function PageLoader() {
  return (
    <div className="flex h-64 items-center justify-center">
      <LoadingSpinner />
    </div>
  );
}

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuthStore();
  const [demoReady, setDemoReady] = useState(false);

  useEffect(() => {
    if (!isAuthenticated && isDemoMode()) {
      loginAsDemo();
      setDemoReady(true);
    }
  }, [isAuthenticated]);

  if (!isAuthenticated && isDemoMode() && !demoReady) {
    return null; // brief flash while demo auth initializes
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
}

/** Detects ?demo=true in the URL and persists it before rendering the app routes. */
function DemoDetector({ children }: { children: React.ReactNode }) {
  const [searchParams] = useSearchParams();
  useEffect(() => {
    if (searchParams.get("demo") === "true") {
      localStorage.setItem("shieldops_demo", "true");
    }
  }, [searchParams]);
  return <>{children}</>;
}

export default function App() {
  const { hydrate } = useAuthStore();

  useEffect(() => {
    hydrate();
  }, [hydrate]);

  return (
    <BrowserRouter>
      <DemoDetector>
        <Suspense fallback={<PageLoader />}>
          <Routes>
            {/* Public routes with landing layout */}
            <Route element={<LandingLayout />}>
              <Route index element={<Landing />} />
              <Route path="products/:productId" element={<ProductLanding />} />
              <Route path="pricing" element={<Pricing />} />
              <Route path="solutions" element={<SEOIndex />} />
              <Route path="solutions/:slug" element={<SEOPage />} />
            </Route>

            {/* Standalone public routes */}
            <Route path="/landing" element={<Navigate to="/" replace />} />
            <Route path="/login" element={<Login />} />

            {/* Dashboard routes under /app */}
            <Route
              path="/app"
              element={
                <ProtectedRoute>
                  <Layout />
                </ProtectedRoute>
              }
            >
              <Route index element={<AgentFactory />} />
              <Route path="agent-task" element={<AgentTask />} />
              <Route path="war-room" element={<WarRoom />} />
              <Route path="agent-history" element={<AgentHistory />} />
              <Route path="schedules" element={<ScheduledTasks />} />
              <Route path="fleet" element={<FleetOverview />} />
              <Route path="investigations" element={<Investigations />} />
              <Route path="investigations/:id" element={<InvestigationDetail />} />
              <Route path="investigations/:id/timeline" element={<IncidentTimeline />} />
              <Route path="remediations" element={<Remediations />} />
              <Route path="remediations/:id" element={<RemediationDetail />} />
              <Route path="security" element={<Security />} />
              <Route path="vulnerabilities" element={<VulnerabilityList />} />
              <Route path="vulnerabilities/:id" element={<VulnerabilityDetailPage />} />
              <Route path="cost" element={<Cost />} />
              <Route path="learning" element={<Learning />} />
              <Route path="analytics" element={<Analytics />} />
              <Route path="agent-performance" element={<AgentPerformance />} />
              <Route path="marketplace" element={<Marketplace />} />
              <Route path="playbooks" element={<Playbooks />} />
              <Route path="playbooks/editor" element={<PlaybookEditor />} />
              <Route path="playbooks/editor/:id" element={<PlaybookEditor />} />
              <Route path="audit-log" element={<AuditLog />} />
              <Route path="compliance" element={<ComplianceDashboard />} />
              <Route path="billing" element={<Billing />} />
              <Route path="system-health" element={<SystemHealth />} />
              <Route path="settings" element={<Settings />} />
              <Route path="users" element={<UserManagement />} />
              <Route path="incidents" element={<IncidentCorrelation />} />
              <Route path="predictions" element={<Predictions />} />
              <Route path="capacity" element={<CapacityForecast />} />
              <Route path="infra-as-code" element={<InfraAsCode />} />
              <Route path="onboarding" element={<OnboardingWizard />} />
              <Route path="pipeline" element={<PipelineRuns />} />
              <Route path="api-keys" element={<APIKeys />} />
              <Route path="workflows" element={<Workflows />} />
              <Route path="mcp-servers" element={<MCPServers />} />
              <Route path="chatops" element={<ChatOps />} />
              <Route path="integrations" element={<EnterpriseIntegrations />} />
              <Route path="automation" element={<AutomationRules />} />
              <Route path="telemetry-optimizer" element={<TelemetryOptimizer />} />
              <Route path="risk-scoring" element={<RiskScoring />} />
              <Route path="otel-pipeline" element={<OTelPipeline />} />
              <Route path="threat-intel" element={<ThreatIntel />} />
              <Route path="incident-commander" element={<IncidentCommander />} />
              <Route path="compliance-audit" element={<ComplianceAudit />} />
              <Route path="otel-collector-manager" element={<OTelCollectorManager />} />
              <Route path="adaptive-security" element={<AdaptiveSecurity />} />
              <Route path="otel-deployer" element={<OTelDeployer />} />
              <Route path="security-posture" element={<SecurityPosture />} />
              <Route path="otel-semantic" element={<OTelSemantic />} />
              <Route path="soar-workflow" element={<SOARWorkflow />} />
              <Route path="tail-sampling" element={<TailSampling />} />
              <Route path="detection-engineering" element={<DetectionEngineering />} />
              <Route path="metrics-pipeline" element={<MetricsPipeline />} />
              <Route path="security-testing" element={<SecurityTesting />} />
              <Route path="logs-pipeline" element={<LogsPipeline />} />
              <Route path="threat-modeling" element={<ThreatModeling />} />
              <Route path="situations" element={<Situations />} />
              <Route path="situations/:id" element={<SituationDetail />} />
              <Route path="agent-firewall" element={<AgentFirewall />} />
              <Route path="nhi-registry" element={<NHIRegistry />} />
              <Route path="mcp-security" element={<MCPSecurity />} />
              <Route path="data-pipeline-security" element={<DataPipelineSecurity />} />
              <Route path="credential-lifecycle" element={<CredentialLifecycle />} />
              <Route path="vendor-normalizer" element={<VendorNormalizer />} />
              <Route path="attack-campaign" element={<AttackCampaign />} />
              <Route path="situation-composer" element={<SituationComposer />} />
              <Route path="compliance-reporter" element={<ComplianceReporter />} />
              <Route path="oauth-analyzer" element={<OAuthAnalyzer />} />
              <Route path="lateral-movement" element={<LateralMovement />} />
              <Route path="shadow-ai-discovery" element={<ShadowAIDiscovery />} />
              <Route path="secrets-scanner" element={<SecretsScanner />} />
              <Route path="api-security" element={<APISecurity />} />
              <Route path="policy-engine" element={<PolicyEngine />} />
              <Route path="cloud-posture" element={<CloudPosture />} />
              <Route path="container-security" element={<ContainerSecurity />} />
              <Route path="supply-chain-security" element={<SupplyChainSecurity />} />
              <Route path="incident-triage" element={<IncidentTriage />} />
              <Route path="change-risk-analyzer" element={<ChangeRiskAnalyzer />} />
              <Route path="cost-anomaly" element={<CostAnomaly />} />
              <Route path="adversarial-validation" element={<AdversarialValidation />} />
              <Route path="mcp-gateway" element={<MCPGateway />} />
              <Route path="service-account-tracker" element={<ServiceAccountTracker />} />
              <Route path="data-classification" element={<DataClassification />} />
              <Route path="access-review" element={<AccessReview />} />
              <Route path="runbook-automation" element={<RunbookAutomation />} />
              <Route path="capacity-planner" element={<CapacityPlanner />} />
              <Route path="disaster-recovery" element={<DisasterRecovery />} />
              <Route path="log-analyzer" element={<LogAnalyzer />} />
              <Route path="chaos-engineering" element={<ChaosEngineering />} />
              <Route path="sla-monitor" element={<SLAMonitor />} />
              <Route path="config-validator" element={<ConfigValidator />} />
              <Route path="network-segmentation" element={<NetworkSegmentation />} />
              <Route path="workflow-engine" element={<WorkflowEngine />} />
              <Route path="alert-correlation" element={<AlertCorrelation />} />
              <Route path="performance-profiler" element={<PerformanceProfiler />} />
              <Route path="anomaly-detector" element={<AnomalyDetector />} />
              <Route path="certificate-manager" element={<CertificateManager />} />
              <Route path="dns-security" element={<DNSSecurity />} />
              <Route path="backup-validator" element={<BackupValidator />} />
              <Route path="vulnerability-manager" element={<VulnerabilityManager />} />
              <Route path="compliance-scanner" element={<ComplianceScanner />} />
              <Route path="threat-response" element={<ThreatResponse />} />
              <Route path="agent-governance" element={<AgentGovernance />} />
              <Route path="model-security" element={<ModelSecurity />} />
              <Route path="prompt-shield" element={<PromptShield />} />
              <Route path="multi-agent-security" element={<MultiAgentSecurity />} />
              <Route path="ai-compliance" element={<AICompliance />} />
              <Route path="digital-twin-security" element={<DigitalTwinSecurity />} />
              <Route path="agentic-mdr" element={<AgenticMDR />} />
              <Route path="breakout-defender" element={<BreakoutDefender />} />
              <Route path="ai-triage-accelerator" element={<AITriageAccelerator />} />
              <Route path="soc-transformation" element={<SOCTransformation />} />
              <Route path="cloud-risk-ranker" element={<CloudRiskRanker />} />
              <Route path="data-loss-prevention" element={<DataLossPrevention />} />
              <Route path="autonomous-xdr" element={<AutonomousXDR />} />
              <Route path="autonomous-soc" element={<AutonomousSOC />} />
              <Route path="cnapp-analyzer" element={<CNAPPAnalyzer />} />
              <Route path="zero-trust-network" element={<ZeroTrustNetwork />} />
              <Route path="intelligent-soar" element={<IntelligentSOAR />} />
              <Route path="malware-analyzer" element={<MalwareAnalyzer />} />
              <Route path="cyber-recovery" element={<CyberRecovery />} />
              <Route path="data-threat-hunting" element={<DataThreatHunting />} />
              <Route path="sensitive-data-monitor" element={<SensitiveDataMonitor />} />
              <Route path="identity-protection" element={<IdentityProtection />} />
              <Route path="exposure-management" element={<ExposureManagement />} />
              <Route path="ai-soc-assistant" element={<AISOCAssistant />} />
              <Route path="log-intelligence" element={<LogIntelligence />} />
              <Route path="insider-threat" element={<InsiderThreat />} />
              <Route path="ransomware-forensics" element={<RansomwareForensics />} />
              <Route path="threat-intel-platform" element={<ThreatIntelligencePlatform />} />
              <Route path="code-security-scanner" element={<CodeSecurityScanner />} />
              <Route path="data-resilience" element={<DataResilience />} />
              <Route path="managed-threat-hunting" element={<ManagedThreatHunting />} />
              <Route path="vulnerability-intelligence" element={<VulnerabilityIntelligence />} />
              <Route path="file-integrity-monitor" element={<FileIntegrityMonitor />} />
              <Route path="iot-ot-security" element={<IoTOTSecurity />} />
              <Route path="security-app-builder" element={<SecurityAppBuilder />} />
              <Route path="air-gap-vault" element={<AirGapVault />} />
              <Route path="agent-memory-store" element={<AgentMemoryStore />} />
              <Route path="reflection-engine" element={<ReflectionEngine />} />
              <Route path="supply-chain-scanner" element={<SupplyChainScanner />} />
              <Route path="cross-vendor-correlator" element={<CrossVendorCorrelator />} />
              <Route path="situation-manager" element={<SituationManager />} />
              <Route path="trust-relationship-mapper" element={<TrustRelationshipMapper />} />
              <Route path="it-asset-intelligence" element={<ITAssetIntelligence />} />
              <Route path="ai-runtime-guardian" element={<AIRuntimeGuardian />} />
              <Route path="data-intelligence" element={<DataIntelligence />} />
              <Route path="endpoint-dlp" element={<EndpointDLP />} />
              <Route path="unified-cloud-security" element={<UnifiedCloudSecurity />} />
              <Route path="backup-security-posture" element={<BackupSecurityPosture />} />
              <Route path="network-pentest" element={<NetworkPentest />} />
              <Route path="web-app-scanner" element={<WebAppScanner />} />
              <Route path="cloud-pentest" element={<CloudPentest />} />
              <Route path="api-pentest" element={<APIPentest />} />
              <Route path="credential-tester" element={<CredentialTester />} />
              <Route path="phishing-simulator" element={<PhishingSimulator />} />
              <Route path="patch-orchestrator" element={<PatchOrchestrator />} />
              <Route path="config-remediation" element={<ConfigRemediation />} />
              <Route path="access-remediation" element={<AccessRemediation />} />
              <Route path="vulnerability-remediation" element={<VulnerabilityRemediation />} />
              <Route path="remediation-verifier" element={<RemediationVerifier />} />
              <Route path="remediation-orchestrator" element={<RemediationOrchestrator />} />
              <Route path="mitre-coverage" element={<MITRECoverage />} />
              <Route path="detection-gaps" element={<DetectionGapFinder />} />
              <Route path="security-scorecard" element={<SecurityScorecard />} />
              <Route path="compliance-gaps" element={<ComplianceGapAnalyzer />} />
              <Route path="attack-readiness" element={<AttackReadiness />} />
              <Route path="executive-reports" element={<ExecutiveReporter />} />
              <Route path="security-pipeline" element={<SecurityPipeline2 />} />
              <Route path="finding-correlator" element={<FindingCorrelator />} />
              <Route path="auto-tickets" element={<AutoTicketManager />} />
              <Route path="continuous-scanner" element={<ContinuousScanner />} />
              <Route path="risk-prioritizer" element={<RiskPrioritizer />} />
              <Route path="security-dashboard-agg" element={<SecurityDashboardAggregator />} />
            </Route>

            {/* Catch-all */}
            <Route path="*" element={<NotFound />} />
          </Routes>
        </Suspense>
      </DemoDetector>
    </BrowserRouter>
  );
}
