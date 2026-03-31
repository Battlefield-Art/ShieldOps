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
const AgentEvolution = lazy(() => import("./pages/AgentEvolution"));
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
const APTEmulator = lazy(() => import("./pages/APTEmulator"));
const PurpleTeam = lazy(() => import("./pages/PurpleTeam"));
const ThreatScenarioRunner = lazy(() => import("./pages/ThreatScenarioRunner"));
const AgentFleetOptimizer = lazy(() => import("./pages/AgentFleetOptimizer"));
const SecurityDataLake = lazy(() => import("./pages/SecurityDataLake"));
const CustomAgentFactory2 = lazy(() => import("./pages/CustomAgentFactory"));
const SecurityDashboardAggregator = lazy(() => import("./pages/SecurityDashboardAggregator"));
const ExecutiveReporter = lazy(() => import("./pages/ExecutiveReporter"));
const RemediationOrchestrator = lazy(() => import("./pages/RemediationOrchestrator"));
const PhishingSimulator = lazy(() => import("./pages/PhishingSimulator"));

const IRPlaybook = lazy(() => import("./pages/IRPlaybook"));
const IncidentCommunicator = lazy(
  () => import("./pages/IncidentCommunicator"),
);
const EvidenceCollector = lazy(
  () => import("./pages/EvidenceCollector"),
);
const PostIncidentAnalyzer = lazy(
  () => import("./pages/PostIncidentAnalyzer"),
);
const IncidentSimulator2 = lazy(
  () => import("./pages/IncidentSimulator2"),
);

const ThreatFeedManager = lazy(
  () => import("./pages/ThreatFeedManager"),
);
const IOCLifecycle = lazy(
  () => import("./pages/IOCLifecycle"),
);
const ThreatAttribution = lazy(
  () => import("./pages/ThreatAttribution"),
);
const SecurityAwareness = lazy(
  () => import("./pages/SecurityAwareness"),
);
const ComplianceWorkflow = lazy(
  () => import("./pages/ComplianceWorkflow"),
);
const GovernanceDashboard = lazy(
  () => import("./pages/GovernanceDashboard"),
);

const DataEncryptionMonitor = lazy(
  () => import("./pages/DataEncryptionMonitor"),
);
const PrivilegeEscalationDetector = lazy(
  () => import("./pages/PrivilegeEscalationDetector"),
);
const SessionHijackDetector = lazy(
  () => import("./pages/SessionHijackDetector"),
);
const APIRateLimiter = lazy(
  () => import("./pages/APIRateLimiter"),
);
const VulnerabilityLifecycle = lazy(
  () => import("./pages/VulnerabilityLifecycle"),
);
const AssetInventory = lazy(
  () => import("./pages/AssetInventory"),
);

const NetworkTrafficAnalyzer = lazy(
  () => import("./pages/NetworkTrafficAnalyzer"),
);
const FirewallRuleAuditor = lazy(
  () => import("./pages/FirewallRuleAuditor"),
);
const WAFManager = lazy(
  () => import("./pages/WAFManager"),
);
const PacketInspector = lazy(
  () => import("./pages/PacketInspector"),
);
const NetworkForensics = lazy(
  () => import("./pages/NetworkForensics"),
);
const BandwidthAnomalyDetector = lazy(
  () => import("./pages/BandwidthAnomalyDetector"),
);

const SASTScanner = lazy(() => import("./pages/SASTScanner"));
const DASTRunner = lazy(() => import("./pages/DASTRunner"));
const SCADependencyChecker = lazy(
  () => import("./pages/SCADependencyChecker"),
);
const ContainerImageScanner = lazy(
  () => import("./pages/ContainerImageScanner"),
);
const IACSecurityScanner = lazy(
  () => import("./pages/IACSecurityScanner"),
);
const SecretsInCodeDetector = lazy(
  () => import("./pages/SecretsInCodeDetector"),
);

const EndpointBehaviorMonitor = lazy(
  () => import("./pages/EndpointBehaviorMonitor"),
);
const MobileDeviceManager = lazy(
  () => import("./pages/MobileDeviceManager"),
);
const BrowserIsolation = lazy(
  () => import("./pages/BrowserIsolation"),
);
const USBDeviceController = lazy(
  () => import("./pages/USBDeviceController"),
);
const PatchComplianceChecker = lazy(
  () => import("./pages/PatchComplianceChecker"),
);
const EndpointForensics = lazy(
  () => import("./pages/EndpointForensics"),
);

const CloudAuditLogger = lazy(() => import("./pages/CloudAuditLogger"));
const ServerlessSecurity = lazy(() => import("./pages/ServerlessSecurity"));
const CloudWorkloadProtector = lazy(
  () => import("./pages/CloudWorkloadProtector"),
);
const MultiCloudCompliance = lazy(
  () => import("./pages/MultiCloudCompliance"),
);
const CloudIdentityFederation = lazy(
  () => import("./pages/CloudIdentityFederation"),
);
const CloudStorageScanner = lazy(
  () => import("./pages/CloudStorageScanner"),
);

// Phase M: Email & Communication Security
const EmailGatewayAnalyzer = lazy(() => import("./pages/EmailGatewayAnalyzer"));
const PhishingEmailAnalyzer = lazy(() => import("./pages/PhishingEmailAnalyzer"));
const SpamFilterManager = lazy(() => import("./pages/SpamFilterManager"));
const EmailDLPMonitor = lazy(() => import("./pages/EmailDLPMonitor"));
const CommunicationAuditor = lazy(() => import("./pages/CommunicationAuditor"));
const SocialEngineeringDetector = lazy(
  () => import("./pages/SocialEngineeringDetector"),
);

// Phase N: Compliance & Regulatory
const GDPRProcessor = lazy(() => import("./pages/GDPRProcessor"));
const HIPAAMonitor = lazy(() => import("./pages/HIPAAMonitor"));
const PCIScanner = lazy(() => import("./pages/PCIScanner"));
const SOXAuditor = lazy(() => import("./pages/SOXAuditor"));
const ISO27001Assessor = lazy(() => import("./pages/ISO27001Assessor"));
const NISTFrameworkMapper = lazy(() => import("./pages/NISTFrameworkMapper"));

// Phase O: AI/ML Security
const ModelDriftDetector = lazy(() => import("./pages/ModelDriftDetector"));
const TrainingDataValidator = lazy(() => import("./pages/TrainingDataValidator"));
const InferenceAttackDetector = lazy(
  () => import("./pages/InferenceAttackDetector"),
);
const ModelExplainabilityAuditor = lazy(
  () => import("./pages/ModelExplainabilityAuditor"),
);
const AIBiasScanner = lazy(() => import("./pages/AIBiasScanner"));
const FederatedLearningSecurity = lazy(
  () => import("./pages/FederatedLearningSecurity"),
);

// Phase P: Physical & OT Security
const PhysicalAccessMonitor = lazy(() => import("./pages/PhysicalAccessMonitor"));
const CCTVAnalytics = lazy(() => import("./pages/CCTVAnalytics"));
const EnvironmentalMonitor = lazy(() => import("./pages/EnvironmentalMonitor"));
const SCADASecurityAnalyzer = lazy(() => import("./pages/SCADASecurityAnalyzer"));
const IndustrialProtocolAnalyzer = lazy(
  () => import("./pages/IndustrialProtocolAnalyzer"),
);
const BuildingManagementSecurity = lazy(
  () => import("./pages/BuildingManagementSecurity"),
);

// Phase Q-T
const DarkWebMonitor = lazy(() => import("./pages/DarkWebMonitor"));
const BrandProtectionScanner = lazy(() => import("./pages/BrandProtectionScanner"));
const ThreatLandscapeMapper = lazy(() => import("./pages/ThreatLandscapeMapper"));
const KillChainAnalyzer = lazy(() => import("./pages/KillChainAnalyzer"));
const AdversaryEmulator = lazy(() => import("./pages/AdversaryEmulator"));
const HuntHypothesisGenerator = lazy(() => import("./pages/HuntHypothesisGenerator"));
const AlertEnrichmentEngine = lazy(() => import("./pages/AlertEnrichmentEngine"));
const TicketAutomation = lazy(() => import("./pages/TicketAutomation"));
const ShiftHandoffManager = lazy(() => import("./pages/ShiftHandoffManager"));
const SOCMetricsDashboard = lazy(() => import("./pages/SOCMetricsDashboard"));
const PlaybookOptimizer = lazy(() => import("./pages/PlaybookOptimizer"));
const WarGamingSimulator = lazy(() => import("./pages/WarGamingSimulator"));
const DataMaskingEngine = lazy(() => import("./pages/DataMaskingEngine"));
const TokenizationManager = lazy(() => import("./pages/TokenizationManager"));
const PrivacyImpactAssessor = lazy(() => import("./pages/PrivacyImpactAssessor"));
const DataLineageTracker = lazy(() => import("./pages/DataLineageTracker"));
const ConsentManager = lazy(() => import("./pages/ConsentManager"));
const DataBreachResponder = lazy(() => import("./pages/DataBreachResponder"));
const ZeroTrustValidator = lazy(() => import("./pages/ZeroTrustValidator"));
const MicroSegmentationPlanner = lazy(() => import("./pages/MicroSegmentationPlanner"));
const SecurityArchitectureReviewer = lazy(
  () => import("./pages/SecurityArchitectureReviewer"),
);
const ThreatSurfaceMinimizer = lazy(() => import("./pages/ThreatSurfaceMinimizer"));
const DefenseInDepthAuditor = lazy(() => import("./pages/DefenseInDepthAuditor"));
const SecurityControlMapper = lazy(() => import("./pages/SecurityControlMapper"));

// Phase U-W
const VendorRiskAssessor = lazy(() => import("./pages/VendorRiskAssessor"));
const SBOMAnalyzer = lazy(() => import("./pages/SBOMAnalyzer"));
const DependencyGraphAnalyzer = lazy(() => import("./pages/DependencyGraphAnalyzer"));
const OpenSourceLicenseScanner = lazy(() => import("./pages/OpenSourceLicenseScanner"));
const ArtifactIntegrityChecker = lazy(() => import("./pages/ArtifactIntegrityChecker"));
const CICDSecurityAuditor = lazy(() => import("./pages/CICDSecurityAuditor"));
const MFAComplianceChecker = lazy(() => import("./pages/MFAComplianceChecker"));
const OrphanAccountDetector = lazy(() => import("./pages/OrphanAccountDetector"));
const PermissionCreepAnalyzer = lazy(() => import("./pages/PermissionCreepAnalyzer"));
const JustInTimeAccess = lazy(() => import("./pages/JustInTimeAccess"));
const CredentialRotationManager = lazy(() => import("./pages/CredentialRotationManager"));
const PrivilegedSessionRecorder = lazy(() => import("./pages/PrivilegedSessionRecorder"));
const IncidentPredictionEngine = lazy(() => import("./pages/IncidentPredictionEngine"));
const IncidentCostCalculator = lazy(() => import("./pages/IncidentCostCalculator"));
const IncidentSimilarityEngine = lazy(() => import("./pages/IncidentSimilarityEngine"));
const ThreatBriefGenerator = lazy(() => import("./pages/ThreatBriefGenerator"));
const SLABreachPredictor = lazy(() => import("./pages/SLABreachPredictor"));
const RunbookKnowledgeBase = lazy(() => import("./pages/RunbookKnowledgeBase"));

// Phase X: Cryptographic Security & Post-Quantum Readiness
const QuantumRiskAssessor = lazy(() => import("./pages/QuantumRiskAssessor"));
const CryptoAgilityManager = lazy(() => import("./pages/CryptoAgilityManager"));
const KeyLifecycleManager = lazy(() => import("./pages/KeyLifecycleManager"));
const PrivacyEngineering = lazy(() => import("./pages/PrivacyEngineering"));
const DataSovereigntyEnforcer = lazy(() => import("./pages/DataSovereigntyEnforcer"));
const DeepfakeDetector = lazy(() => import("./pages/DeepfakeDetector"));

// Phase Y: Autonomous Security Operations & Intelligence Automation
const ThreatCorrelationEngine = lazy(() => import("./pages/ThreatCorrelationEngine"));
const SecurityCopilot = lazy(() => import("./pages/SecurityCopilot"));
const ComplianceAutomationEngine = lazy(() => import("./pages/ComplianceAutomationEngine"));
const IncidentPlaybookGenerator = lazy(() => import("./pages/IncidentPlaybookGenerator"));
const AttackPathAnalyzer = lazy(() => import("./pages/AttackPathAnalyzer"));
const SecurityMetricsCollector = lazy(() => import("./pages/SecurityMetricsCollector"));

// Phase Z: Threat Intelligence Fusion & Response Automation
const ThreatFeedAggregator = lazy(() => import("./pages/ThreatFeedAggregator"));
const IOCEnrichmentEngine = lazy(() => import("./pages/IOCEnrichmentEngine"));
const ResponseAutomationEngine = lazy(() => import("./pages/ResponseAutomationEngine"));
const RiskQuantificationEngine = lazy(() => import("./pages/RiskQuantificationEngine"));
const SecurityAwarenessTrainer = lazy(() => import("./pages/SecurityAwarenessTrainer"));
const ThreatHuntAutomation = lazy(() => import("./pages/ThreatHuntAutomation"));

// Phase AA: Platform Hardening & Operational Maturity
const APIGatewaySecurity = lazy(() => import("./pages/APIGatewaySecurity"));
const SessionManager = lazy(() => import("./pages/SessionManager"));
const RateLimitEnforcer = lazy(() => import("./pages/RateLimitEnforcer"));
const HealthCheckOrchestrator = lazy(() => import("./pages/HealthCheckOrchestrator"));
const ConfigurationAuditor = lazy(() => import("./pages/ConfigurationAuditor"));
const DeploymentGuardian = lazy(() => import("./pages/DeploymentGuardian"));

// Phase AB: Advanced Analytics & Intelligence
const BehavioralAnalyticsEngine = lazy(() => import("./pages/BehavioralAnalyticsEngine"));
const AnomalyPredictionEngine = lazy(() => import("./pages/AnomalyPredictionEngine"));
const RootCauseAnalyzer = lazy(() => import("./pages/RootCauseAnalyzer"));
const CapacityIntelligence = lazy(() => import("./pages/CapacityIntelligence"));
const ServiceDependencyMapper = lazy(() => import("./pages/ServiceDependencyMapper"));
const PerformanceBaselineEngine = lazy(() => import("./pages/PerformanceBaselineEngine"));

// Phase AC: Compliance Deepening & Regulatory Automation
const RegulatoryChangeTracker = lazy(() => import("./pages/RegulatoryChangeTracker"));
const EvidenceAutomationEngine = lazy(() => import("./pages/EvidenceAutomationEngine"));
const VendorComplianceAssessor = lazy(() => import("./pages/VendorComplianceAssessor"));
const DataRetentionEnforcer = lazy(() => import("./pages/DataRetentionEnforcer"));
const PrivacyConsentManager = lazy(() => import("./pages/PrivacyConsentManager"));
const AuditTrailAnalyzer = lazy(() => import("./pages/AuditTrailAnalyzer"));

// Phase AD: Incident Lifecycle & War Room Automation
const IncidentEscalationEngine = lazy(() => import("./pages/IncidentEscalationEngine"));
const WarRoomAutomator = lazy(() => import("./pages/WarRoomAutomator"));
const StakeholderNotifier = lazy(() => import("./pages/StakeholderNotifier"));
const PostmortemGenerator = lazy(() => import("./pages/PostmortemGenerator"));
const SLAViolationDetector = lazy(() => import("./pages/SLAViolationDetector"));
const OnCallOptimizer = lazy(() => import("./pages/OnCallOptimizer"));

// Phase AE: Cloud Infrastructure & Cost Intelligence
const CloudCostOptimizer = lazy(() => import("./pages/CloudCostOptimizer"));
const InfrastructureDriftDetector = lazy(() => import("./pages/InfrastructureDriftDetector"));
const ResourceRightsizer = lazy(() => import("./pages/ResourceRightsizer"));
const MultiCloudOrchestrator = lazy(() => import("./pages/MultiCloudOrchestrator"));
const CloudMigrationPlanner = lazy(() => import("./pages/CloudMigrationPlanner"));
const FinopsForecaster = lazy(() => import("./pages/FinopsForecaster"));

// ── Phase AF ──────────────────────────────────────────────────────
const PredictiveScaler = lazy(() => import("./pages/PredictiveScaler"));
const ComplianceWorkflow = lazy(() => import("./pages/ComplianceWorkflow"));
const ServiceHealthMonitor = lazy(() => import("./pages/ServiceHealthMonitor"));
const CloudWorkloadProtector = lazy(() => import("./pages/CloudWorkloadProtector"));

// ── Phase AG ──────────────────────────────────────────────────────
const ComplianceGapAnalyzer = lazy(() => import("./pages/ComplianceGapAnalyzer"));
const NetworkTrafficAnalyzer = lazy(() => import("./pages/NetworkTrafficAnalyzer"));
const SecretRotationManager = lazy(() => import("./pages/SecretRotationManager"));
const IncidentPlaybookEngine = lazy(() => import("./pages/IncidentPlaybookEngine"));
const CloudStorageScanner = lazy(() => import("./pages/CloudStorageScanner"));

// ── Phase AH ──────────────────────────────────────────────────────
const ThreatFeedAggregator = lazy(() => import("./pages/ThreatFeedAggregator"));
const IAMPolicyAnalyzer = lazy(() => import("./pages/IAMPolicyAnalyzer"));
const ObservabilityPipelineOptimizer = lazy(() => import("./pages/ObservabilityPipelineOptimizer"));
const DatabaseSecurityScanner = lazy(() => import("./pages/DatabaseSecurityScanner"));
const EndpointProtectionManager = lazy(() => import("./pages/EndpointProtectionManager"));
const SecurityAwarenessEngine = lazy(() => import("./pages/SecurityAwarenessEngine"));

// ── Phase AI ──────────────────────────────────────────────────────
const VulnerabilityPrioritizer = lazy(() => import("./pages/VulnerabilityPrioritizer"));
const DataPipelineProtector = lazy(() => import("./pages/DataPipelineProtector"));
const CloudPermissionAuditor = lazy(() => import("./pages/CloudPermissionAuditor"));
const IncidentTimelineBuilder = lazy(() => import("./pages/IncidentTimelineBuilder"));
const SOCMetricsAnalyzer = lazy(() => import("./pages/SOCMetricsAnalyzer"));
const AutomatedPentest = lazy(() => import("./pages/AutomatedPentest"));

// ── Phase AJ ──────────────────────────────────────────────────────
const AttackSurfaceMapper = lazy(() => import("./pages/AttackSurfaceMapper"));
const DNSThreatAnalyzer = lazy(() => import("./pages/DNSThreatAnalyzer"));
const CertificateLifecycleManager = lazy(() => import("./pages/CertificateLifecycleManager"));
const SecurityConfigAssessor = lazy(() => import("./pages/SecurityConfigAssessor"));
const CloudNetworkFirewall = lazy(() => import("./pages/CloudNetworkFirewall"));
const ThreatHuntOrchestrator = lazy(() => import("./pages/ThreatHuntOrchestrator"));
const NetworkMicrosegmentation = lazy(() => import("./pages/NetworkMicrosegmentation"));
const SupplyChainRiskMonitor = lazy(() => import("./pages/SupplyChainRiskMonitor"));
const DigitalForensicsLab = lazy(() => import("./pages/DigitalForensicsLab"));
const ApiAbuseDetector = lazy(() => import("./pages/ApiAbuseDetector"));
const CloudSecretVault = lazy(() => import("./pages/CloudSecretVault"));
const ComplianceEvidenceCollector = lazy(() => import("./pages/ComplianceEvidenceCollector"));

// ── Phase AK ──────────────────────────────────────────────────────
const EmailSecurityGateway = lazy(() => import("./pages/EmailSecurityGateway"));
const FirmwareSecurityScanner = lazy(() => import("./pages/FirmwareSecurityScanner"));
const ThreatIntelligenceFusion = lazy(() => import("./pages/ThreatIntelligenceFusion"));

// ── Phase AL ──────────────────────────────────────────────────────
const NetworkTrafficInspector = lazy(() => import("./pages/NetworkTrafficInspector"));
const SecurityTrainingPlatform = lazy(() => import("./pages/SecurityTrainingPlatform"));
const ContainerRuntimeProtector = lazy(() => import("./pages/ContainerRuntimeProtector"));
const DataExfiltrationMonitor = lazy(() => import("./pages/DataExfiltrationMonitor"));
const BrowserThreatProtector = lazy(() => import("./pages/BrowserThreatProtector"));
const IdentityThreatDetector = lazy(() => import("./pages/IdentityThreatDetector"));

// ── Phase AM ──────────────────────────────────────────────────────
const SecurityOrchestrationHub = lazy(() => import("./pages/SecurityOrchestrationHub"));
const PrivilegeAccessMonitor = lazy(() => import("./pages/PrivilegeAccessMonitor"));
const VulnerabilityCorrelationEngine = lazy(() => import("./pages/VulnerabilityCorrelationEngine"));
const CloudWorkloadInspector = lazy(() => import("./pages/CloudWorkloadInspector"));
const LogAnomalyDetector = lazy(() => import("./pages/LogAnomalyDetector"));
const MobileThreatDefender = lazy(() => import("./pages/MobileThreatDefender"));

// ── Phase AN ──────────────────────────────────────────────────────
const DnsFirewallController = lazy(() => import("./pages/DnsFirewallController"));
const SaasSecurityPosture = lazy(() => import("./pages/SaasSecurityPosture"));
const EventStreamProcessor = lazy(() => import("./pages/EventStreamProcessor"));
const DeceptionNetworkManager = lazy(() => import("./pages/DeceptionNetworkManager"));
const BackupIntegrityVerifier = lazy(() => import("./pages/BackupIntegrityVerifier"));
const IncidentCostTracker = lazy(() => import("./pages/IncidentCostTracker"));

// ── Phase AO ──────────────────────────────────────────────────────
const ThreatSimulationEngine = lazy(() => import("./pages/ThreatSimulationEngine"));
const PolicyComplianceEnforcer = lazy(() => import("./pages/PolicyComplianceEnforcer"));
const SecretSprawlDetector = lazy(() => import("./pages/SecretSprawlDetector"));

// ── Phase AO (cont.) ─────────────────────────────────────────────
const CloudEntitlementManager = lazy(() => import("./pages/CloudEntitlementManager"));
const SecurityChaosTester = lazy(() => import("./pages/SecurityChaosTester"));
const WirelessSecurityAuditor = lazy(() => import("./pages/WirelessSecurityAuditor"));

// ── Phase AP ──────────────────────────────────────────────────────
const MLModelScanner = lazy(() => import("./pages/MLModelScanner"));
const RegulatoryChangeMonitor = lazy(() => import("./pages/RegulatoryChangeMonitor"));
const DataPrivacyScanner = lazy(() => import("./pages/DataPrivacyScanner"));
const KubernetesPolicyEngine = lazy(() => import("./pages/KubernetesPolicyEngine"));
const SIEMRuleOptimizer = lazy(() => import("./pages/SIEMRuleOptimizer"));
const ThirdPartyRiskMonitor = lazy(() => import("./pages/ThirdPartyRiskMonitor"));

// ── Phase AQ ──────────────────────────────────────────────────────
const ShadowAPIDetector = lazy(() => import("./pages/ShadowAPIDetector"));
const SecurityDataMesh = lazy(() => import("./pages/SecurityDataMesh"));
const AttackNarrativeBuilder = lazy(() => import("./pages/AttackNarrativeBuilder"));

// ── Phase AJ ─────────────────────────────────────────────────────
const AgentlessScanner = lazy(() => import("./pages/AgentlessScanner"));
const ToxicCombinationDetector = lazy(() => import("./pages/ToxicCombinationDetector"));
const AutonomousResponseEngine = lazy(() => import("./pages/AutonomousResponseEngine"));

// ── Phase AR ─────────────────────────────────────────────────────
const CloudKeyManager = lazy(() => import("./pages/CloudKeyManager"));
const SecurityPostureScorer = lazy(() => import("./pages/SecurityPostureScorer"));
const AlertFatigueReducer = lazy(() => import("./pages/AlertFatigueReducer"));

// ── Phase AK (cont.) ────────────────────────────────
const DependencyVulnerabilityTracker = lazy(() => import("./pages/DependencyVulnerabilityTracker"));
const SecurityBudgetOptimizer = lazy(() => import("./pages/SecurityBudgetOptimizer"));
const CloudDriftRemediator = lazy(() => import("./pages/CloudDriftRemediator"));

// ── Phase AS ─────────────────────────────────────────────────────
const SecurityKnowledgeGraph = lazy(() => import("./pages/SecurityKnowledgeGraph"));
const ComplianceDriftMonitor = lazy(() => import("./pages/ComplianceDriftMonitor"));
const IncidentPredictionModel = lazy(() => import("./pages/IncidentPredictionModel"));
const AIModelGovernance = lazy(() => import("./pages/AIModelGovernance"));
const QuantumSafeAuditor = lazy(() => import("./pages/QuantumSafeAuditor"));
const MultiCloudPosture = lazy(() => import("./pages/MultiCloudPosture"));

// ── Phase AT (new agents) ───────────────────────────────────────
const APISchemaValidator = lazy(() => import("./pages/APISchemaValidator"));
const SecurityAutomationPipeline = lazy(() => import("./pages/SecurityAutomationPipeline"));
const UnifiedThreatModel2 = lazy(() => import("./pages/UnifiedThreatModel"));

// ── Phase AU ─────────────────────────────────────────────────────
const InsiderRiskScorer = lazy(() => import("./pages/InsiderRiskScorer"));
const SecurityMetricDashboard = lazy(() => import("./pages/SecurityMetricDashboard"));
const ZeroDayHunter = lazy(() => import("./pages/ZeroDayHunter"));

// ── Phase AV ─────────────────────────────────────────────────────
const RuntimeApplicationProtector = lazy(() => import("./pages/RuntimeApplicationProtector"));
const CertificateTransparencyMonitor = lazy(() => import("./pages/CertificateTransparencyMonitor"));
const AccessCertificationEngine = lazy(() => import("./pages/AccessCertificationEngine"));

// ── Phase AW (new agents) ───────────────────────────────────────
const CloudCostAnomalyDetector = lazy(() => import("./pages/CloudCostAnomalyDetector"));
const SecurityWorkflowBuilder = lazy(() => import("./pages/SecurityWorkflowBuilder"));
const AssetExposureScorer = lazy(() => import("./pages/AssetExposureScorer"));

// ── Phase AX (new agents) ───────────────────────────────────────
const SecurityCopilotAgent = lazy(() => import("./pages/SecurityCopilotAgent"));
const CloudNetworkAnalyzer = lazy(() => import("./pages/CloudNetworkAnalyzer"));
const ThreatFeedOrchestrator = lazy(() => import("./pages/ThreatFeedOrchestrator"));

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
              <Route path="evolution" element={<AgentEvolution />} />
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
              <Route path="apt-emulator" element={<APTEmulator />} />
              <Route path="purple-team" element={<PurpleTeam />} />
              <Route path="threat-scenarios" element={<ThreatScenarioRunner />} />
              <Route path="fleet-optimizer" element={<AgentFleetOptimizer />} />
              <Route path="security-data-lake" element={<SecurityDataLake />} />
              <Route path="agent-factory" element={<CustomAgentFactory2 />} />
              <Route path="ir-playbook" element={<IRPlaybook />} />
              <Route path="incident-communicator" element={<IncidentCommunicator />} />
              <Route path="evidence-collector" element={<EvidenceCollector />} />
              <Route path="post-incident-analyzer" element={<PostIncidentAnalyzer />} />
              <Route path="incident-simulator" element={<IncidentSimulator2 />} />
              <Route path="threat-feed-manager" element={<ThreatFeedManager />} />
              <Route path="ioc-lifecycle" element={<IOCLifecycle />} />
              <Route path="threat-attribution" element={<ThreatAttribution />} />
              <Route path="security-awareness" element={<SecurityAwareness />} />
              <Route path="compliance-workflow" element={<ComplianceWorkflow />} />
              <Route path="governance-dashboard" element={<GovernanceDashboard />} />
              <Route path="data-encryption-monitor" element={<DataEncryptionMonitor />} />
              <Route path="privilege-escalation" element={<PrivilegeEscalationDetector />} />
              <Route path="session-hijack" element={<SessionHijackDetector />} />
              <Route path="api-rate-limiter" element={<APIRateLimiter />} />
              <Route path="vulnerability-lifecycle" element={<VulnerabilityLifecycle />} />
              <Route path="asset-inventory" element={<AssetInventory />} />
              <Route path="network-traffic-analyzer" element={<NetworkTrafficAnalyzer />} />
              <Route path="firewall-rule-auditor" element={<FirewallRuleAuditor />} />
              <Route path="waf-manager" element={<WAFManager />} />
              <Route path="packet-inspector" element={<PacketInspector />} />
              <Route path="network-forensics" element={<NetworkForensics />} />
              <Route path="bandwidth-anomaly" element={<BandwidthAnomalyDetector />} />
              <Route path="sast-scanner" element={<SASTScanner />} />
              <Route path="dast-runner" element={<DASTRunner />} />
              <Route path="sca-dependency" element={<SCADependencyChecker />} />
              <Route path="container-image-scanner" element={<ContainerImageScanner />} />
              <Route path="iac-security-scanner" element={<IACSecurityScanner />} />
              <Route path="secrets-in-code" element={<SecretsInCodeDetector />} />
              <Route path="endpoint-behavior" element={<EndpointBehaviorMonitor />} />
              <Route path="mobile-device-manager" element={<MobileDeviceManager />} />
              <Route path="browser-isolation" element={<BrowserIsolation />} />
              <Route path="usb-device-controller" element={<USBDeviceController />} />
              <Route path="patch-compliance" element={<PatchComplianceChecker />} />
              <Route path="endpoint-forensics" element={<EndpointForensics />} />
              <Route path="cloud-audit-logger" element={<CloudAuditLogger />} />
              <Route path="serverless-security" element={<ServerlessSecurity />} />
              <Route path="cloud-workload-protector" element={<CloudWorkloadProtector />} />
              <Route path="multi-cloud-compliance" element={<MultiCloudCompliance />} />
              <Route path="cloud-identity-federation" element={<CloudIdentityFederation />} />
              <Route path="cloud-storage-scanner" element={<CloudStorageScanner />} />
              <Route path="email-gateway" element={<EmailGatewayAnalyzer />} />
              <Route path="phishing-email" element={<PhishingEmailAnalyzer />} />
              <Route path="spam-filter" element={<SpamFilterManager />} />
              <Route path="email-dlp" element={<EmailDLPMonitor />} />
              <Route path="communication-auditor" element={<CommunicationAuditor />} />
              <Route path="social-engineering" element={<SocialEngineeringDetector />} />
              <Route path="gdpr-processor" element={<GDPRProcessor />} />
              <Route path="hipaa-monitor" element={<HIPAAMonitor />} />
              <Route path="pci-scanner" element={<PCIScanner />} />
              <Route path="sox-auditor" element={<SOXAuditor />} />
              <Route path="iso27001-assessor" element={<ISO27001Assessor />} />
              <Route path="nist-framework" element={<NISTFrameworkMapper />} />
              <Route path="model-drift" element={<ModelDriftDetector />} />
              <Route path="training-data" element={<TrainingDataValidator />} />
              <Route path="inference-attack" element={<InferenceAttackDetector />} />
              <Route path="model-explainability" element={<ModelExplainabilityAuditor />} />
              <Route path="ai-bias" element={<AIBiasScanner />} />
              <Route path="federated-learning" element={<FederatedLearningSecurity />} />
              <Route path="physical-access" element={<PhysicalAccessMonitor />} />
              <Route path="cctv-analytics" element={<CCTVAnalytics />} />
              <Route path="environmental-monitor" element={<EnvironmentalMonitor />} />
              <Route path="scada-security" element={<SCADASecurityAnalyzer />} />
              <Route path="industrial-protocol" element={<IndustrialProtocolAnalyzer />} />
              <Route path="building-management" element={<BuildingManagementSecurity />} />
              <Route path="dark-web-monitor" element={<DarkWebMonitor />} />
              <Route path="brand-protection" element={<BrandProtectionScanner />} />
              <Route path="threat-landscape" element={<ThreatLandscapeMapper />} />
              <Route path="kill-chain" element={<KillChainAnalyzer />} />
              <Route path="adversary-emulator" element={<AdversaryEmulator />} />
              <Route path="hunt-hypotheses" element={<HuntHypothesisGenerator />} />
              <Route path="alert-enrichment" element={<AlertEnrichmentEngine />} />
              <Route path="ticket-automation" element={<TicketAutomation />} />
              <Route path="shift-handoff" element={<ShiftHandoffManager />} />
              <Route path="soc-metrics" element={<SOCMetricsDashboard />} />
              <Route path="playbook-optimizer" element={<PlaybookOptimizer />} />
              <Route path="war-gaming" element={<WarGamingSimulator />} />
              <Route path="data-masking" element={<DataMaskingEngine />} />
              <Route path="tokenization" element={<TokenizationManager />} />
              <Route path="privacy-impact" element={<PrivacyImpactAssessor />} />
              <Route path="data-lineage" element={<DataLineageTracker />} />
              <Route path="consent-manager" element={<ConsentManager />} />
              <Route path="breach-response" element={<DataBreachResponder />} />
              <Route path="zero-trust-validator" element={<ZeroTrustValidator />} />
              <Route path="micro-segmentation" element={<MicroSegmentationPlanner />} />
              <Route path="architecture-review" element={<SecurityArchitectureReviewer />} />
              <Route path="threat-surface" element={<ThreatSurfaceMinimizer />} />
              <Route path="defense-in-depth" element={<DefenseInDepthAuditor />} />
              <Route path="control-mapper" element={<SecurityControlMapper />} />
              <Route path="vendor-risk" element={<VendorRiskAssessor />} />
              <Route path="sbom-analyzer" element={<SBOMAnalyzer />} />
              <Route path="dependency-graph" element={<DependencyGraphAnalyzer />} />
              <Route path="license-scanner" element={<OpenSourceLicenseScanner />} />
              <Route path="artifact-integrity" element={<ArtifactIntegrityChecker />} />
              <Route path="cicd-security" element={<CICDSecurityAuditor />} />
              <Route path="mfa-compliance" element={<MFAComplianceChecker />} />
              <Route path="orphan-accounts" element={<OrphanAccountDetector />} />
              <Route path="permission-creep" element={<PermissionCreepAnalyzer />} />
              <Route path="jit-access" element={<JustInTimeAccess />} />
              <Route path="credential-rotation" element={<CredentialRotationManager />} />
              <Route path="session-recorder" element={<PrivilegedSessionRecorder />} />
              <Route path="incident-prediction" element={<IncidentPredictionEngine />} />
              <Route path="incident-cost" element={<IncidentCostCalculator />} />
              <Route path="incident-similarity" element={<IncidentSimilarityEngine />} />
              <Route path="threat-brief" element={<ThreatBriefGenerator />} />
              <Route path="sla-predictor" element={<SLABreachPredictor />} />
              <Route path="runbook-kb" element={<RunbookKnowledgeBase />} />
              <Route path="quantum-risk" element={<QuantumRiskAssessor />} />
              <Route path="crypto-agility" element={<CryptoAgilityManager />} />
              <Route path="key-lifecycle" element={<KeyLifecycleManager />} />
              <Route path="privacy-engineering" element={<PrivacyEngineering />} />
              <Route path="data-sovereignty" element={<DataSovereigntyEnforcer />} />
              <Route path="deepfake-detector" element={<DeepfakeDetector />} />
              <Route path="threat-correlation" element={<ThreatCorrelationEngine />} />
              <Route path="security-copilot" element={<SecurityCopilot />} />
              <Route path="compliance-automation" element={<ComplianceAutomationEngine />} />
              <Route path="playbook-generator" element={<IncidentPlaybookGenerator />} />
              <Route path="attack-path" element={<AttackPathAnalyzer />} />
              <Route path="security-metrics" element={<SecurityMetricsCollector />} />
              <Route path="threat-feed-aggregator" element={<ThreatFeedAggregator />} />
              <Route path="ioc-enrichment" element={<IOCEnrichmentEngine />} />
              <Route path="response-automation" element={<ResponseAutomationEngine />} />
              <Route path="risk-quantification" element={<RiskQuantificationEngine />} />
              <Route path="awareness-trainer" element={<SecurityAwarenessTrainer />} />
              <Route path="threat-hunt-automation" element={<ThreatHuntAutomation />} />
              <Route path="api-gateway-security" element={<APIGatewaySecurity />} />
              <Route path="session-manager" element={<SessionManager />} />
              <Route path="rate-limit-enforcer" element={<RateLimitEnforcer />} />
              <Route path="health-orchestrator" element={<HealthCheckOrchestrator />} />
              <Route path="config-auditor" element={<ConfigurationAuditor />} />
              <Route path="deployment-guardian" element={<DeploymentGuardian />} />
              <Route path="behavioral-analytics" element={<BehavioralAnalyticsEngine />} />
              <Route path="anomaly-prediction" element={<AnomalyPredictionEngine />} />
              <Route path="root-cause" element={<RootCauseAnalyzer />} />
              <Route path="capacity-intelligence" element={<CapacityIntelligence />} />
              <Route path="service-dependencies" element={<ServiceDependencyMapper />} />
              <Route path="performance-baselines" element={<PerformanceBaselineEngine />} />
              <Route path="regulatory-changes" element={<RegulatoryChangeTracker />} />
              <Route path="evidence-automation" element={<EvidenceAutomationEngine />} />
              <Route path="vendor-compliance" element={<VendorComplianceAssessor />} />
              <Route path="data-retention" element={<DataRetentionEnforcer />} />
              <Route path="privacy-consent" element={<PrivacyConsentManager />} />
              <Route path="audit-trail-analyzer" element={<AuditTrailAnalyzer />} />
              <Route path="incident-escalation" element={<IncidentEscalationEngine />} />
              <Route path="war-room-automator" element={<WarRoomAutomator />} />
              <Route path="stakeholder-notifier" element={<StakeholderNotifier />} />
              <Route path="postmortem-generator" element={<PostmortemGenerator />} />
              <Route path="sla-violations" element={<SLAViolationDetector />} />
              <Route path="oncall-optimizer" element={<OnCallOptimizer />} />
              <Route path="cloud-cost-optimizer" element={<CloudCostOptimizer />} />
              <Route path="infra-drift" element={<InfrastructureDriftDetector />} />
              <Route path="resource-rightsizer" element={<ResourceRightsizer />} />
              <Route path="multi-cloud-orchestrator" element={<MultiCloudOrchestrator />} />
              <Route path="cloud-migration-planner" element={<CloudMigrationPlanner />} />
              <Route path="finops-forecaster" element={<FinopsForecaster />} />
              <Route path="predictive-scaler" element={<PredictiveScaler />} />
              <Route path="compliance-workflow" element={<ComplianceWorkflow />} />
              <Route path="service-health-monitor" element={<ServiceHealthMonitor />} />
              <Route path="cloud-workload-protector" element={<CloudWorkloadProtector />} />
              <Route path="compliance-gap-analyzer" element={<ComplianceGapAnalyzer />} />
              <Route path="network-traffic-analyzer" element={<NetworkTrafficAnalyzer />} />
              <Route path="secret-rotation-manager" element={<SecretRotationManager />} />
              <Route path="incident-playbook-engine" element={<IncidentPlaybookEngine />} />
              <Route path="cloud-storage-scanner" element={<CloudStorageScanner />} />
              <Route path="threat-feed-aggregator" element={<ThreatFeedAggregator />} />
              <Route path="iam-policy-analyzer" element={<IAMPolicyAnalyzer />} />
              <Route path="observability-pipeline-optimizer" element={<ObservabilityPipelineOptimizer />} />
              <Route path="database-security-scanner" element={<DatabaseSecurityScanner />} />
              <Route path="endpoint-protection-manager" element={<EndpointProtectionManager />} />
              <Route path="security-awareness-engine" element={<SecurityAwarenessEngine />} />
              <Route path="vulnerability-prioritizer" element={<VulnerabilityPrioritizer />} />
              <Route path="data-pipeline-protector" element={<DataPipelineProtector />} />
              <Route path="cloud-permission-auditor" element={<CloudPermissionAuditor />} />
              <Route path="incident-timeline-builder" element={<IncidentTimelineBuilder />} />
              <Route path="soc-metrics-analyzer" element={<SOCMetricsAnalyzer />} />
              <Route path="automated-pentest" element={<AutomatedPentest />} />
              <Route path="attack-surface-mapper" element={<AttackSurfaceMapper />} />
              <Route path="dns-threat-analyzer" element={<DNSThreatAnalyzer />} />
              <Route path="certificate-lifecycle" element={<CertificateLifecycleManager />} />
              <Route path="security-config-assessor" element={<SecurityConfigAssessor />} />
              <Route path="cloud-network-firewall" element={<CloudNetworkFirewall />} />
              <Route path="threat-hunt-orchestrator" element={<ThreatHuntOrchestrator />} />
              <Route path="network-microsegmentation" element={<NetworkMicrosegmentation />} />
              <Route path="supply-chain-risk-monitor" element={<SupplyChainRiskMonitor />} />
              <Route path="digital-forensics-lab" element={<DigitalForensicsLab />} />
              <Route path="api-abuse-detector" element={<ApiAbuseDetector />} />
              <Route path="cloud-secret-vault" element={<CloudSecretVault />} />
              <Route path="compliance-evidence-collector" element={<ComplianceEvidenceCollector />} />
              <Route path="email-security-gateway" element={<EmailSecurityGateway />} />
              <Route path="firmware-security-scanner" element={<FirmwareSecurityScanner />} />
              <Route path="threat-intel-fusion" element={<ThreatIntelligenceFusion />} />
              <Route path="network-traffic-inspector" element={<NetworkTrafficInspector />} />
              <Route path="security-training-platform" element={<SecurityTrainingPlatform />} />
              <Route path="container-runtime-protector" element={<ContainerRuntimeProtector />} />
              <Route path="data-exfiltration-monitor" element={<DataExfiltrationMonitor />} />
              <Route path="browser-threat-protector" element={<BrowserThreatProtector />} />
              <Route path="identity-threat-detector" element={<IdentityThreatDetector />} />
              <Route path="security-orchestration-hub" element={<SecurityOrchestrationHub />} />
              <Route path="privilege-access-monitor" element={<PrivilegeAccessMonitor />} />
              <Route path="vulnerability-correlation-engine" element={<VulnerabilityCorrelationEngine />} />
              <Route path="cloud-workload-inspector" element={<CloudWorkloadInspector />} />
              <Route path="log-anomaly-detector" element={<LogAnomalyDetector />} />
              <Route path="mobile-threat-defender" element={<MobileThreatDefender />} />
              <Route path="dns-firewall-controller" element={<DnsFirewallController />} />
              <Route path="saas-security-posture" element={<SaasSecurityPosture />} />
              <Route path="event-stream-processor" element={<EventStreamProcessor />} />
              <Route path="deception-network-manager" element={<DeceptionNetworkManager />} />
              <Route path="backup-integrity-verifier" element={<BackupIntegrityVerifier />} />
              <Route path="incident-cost-tracker" element={<IncidentCostTracker />} />
              <Route path="threat-simulation-engine" element={<ThreatSimulationEngine />} />
              <Route path="policy-compliance-enforcer" element={<PolicyComplianceEnforcer />} />
              <Route path="secret-sprawl-detector" element={<SecretSprawlDetector />} />
              <Route path="cloud-entitlement-manager" element={<CloudEntitlementManager />} />
              <Route path="security-chaos-tester" element={<SecurityChaosTester />} />
              <Route path="wireless-security-auditor" element={<WirelessSecurityAuditor />} />
              <Route path="ml-model-scanner" element={<MLModelScanner />} />
              <Route path="regulatory-change-monitor" element={<RegulatoryChangeMonitor />} />
              <Route path="data-privacy-scanner" element={<DataPrivacyScanner />} />
              <Route path="kubernetes-policy-engine" element={<KubernetesPolicyEngine />} />
              <Route path="siem-rule-optimizer" element={<SIEMRuleOptimizer />} />
              <Route path="third-party-risk-monitor" element={<ThirdPartyRiskMonitor />} />
              <Route path="shadow-api-detector" element={<ShadowAPIDetector />} />
              <Route path="security-data-mesh" element={<SecurityDataMesh />} />
              <Route path="attack-narrative-builder" element={<AttackNarrativeBuilder />} />
              <Route path="agentless-scanner" element={<AgentlessScanner />} />
              <Route path="toxic-combination-detector" element={<ToxicCombinationDetector />} />
              <Route path="autonomous-response-engine" element={<AutonomousResponseEngine />} />
              <Route path="dependency-vulnerability-tracker" element={<DependencyVulnerabilityTracker />} />
              <Route path="security-budget-optimizer" element={<SecurityBudgetOptimizer />} />
              <Route path="cloud-drift-remediator" element={<CloudDriftRemediator />} />
              <Route path="cloud-key-manager" element={<CloudKeyManager />} />
              <Route path="security-posture-scorer" element={<SecurityPostureScorer />} />
              <Route path="alert-fatigue-reducer" element={<AlertFatigueReducer />} />
              <Route path="security-knowledge-graph" element={<SecurityKnowledgeGraph />} />
              <Route path="compliance-drift-monitor" element={<ComplianceDriftMonitor />} />
              <Route path="incident-prediction-model" element={<IncidentPredictionModel />} />
              <Route path="ai-model-governance" element={<AIModelGovernance />} />
              <Route path="quantum-safe-auditor" element={<QuantumSafeAuditor />} />
              <Route path="multi-cloud-posture" element={<MultiCloudPosture />} />
              <Route path="insider-risk-scorer" element={<InsiderRiskScorer />} />
              <Route path="security-metric-dashboard" element={<SecurityMetricDashboard />} />
              <Route path="zero-day-hunter" element={<ZeroDayHunter />} />
              <Route path="api-schema-validator" element={<APISchemaValidator />} />
              <Route path="security-automation-pipeline" element={<SecurityAutomationPipeline />} />
              <Route path="unified-threat-model" element={<UnifiedThreatModel2 />} />
              <Route path="runtime-application-protector" element={<RuntimeApplicationProtector />} />
              <Route path="certificate-transparency-monitor" element={<CertificateTransparencyMonitor />} />
              <Route path="access-certification-engine" element={<AccessCertificationEngine />} />
              <Route path="cloud-cost-anomaly-detector" element={<CloudCostAnomalyDetector />} />
              <Route path="security-workflow-builder" element={<SecurityWorkflowBuilder />} />
              <Route path="asset-exposure-scorer" element={<AssetExposureScorer />} />
              <Route path="security-copilot-agent" element={<SecurityCopilotAgent />} />
              <Route path="cloud-network-analyzer" element={<CloudNetworkAnalyzer />} />
              <Route path="threat-feed-orchestrator" element={<ThreatFeedOrchestrator />} />
            </Route>

            {/* Catch-all */}
            <Route path="*" element={<NotFound />} />
          </Routes>
        </Suspense>
      </DemoDetector>
    </BrowserRouter>
  );
}
