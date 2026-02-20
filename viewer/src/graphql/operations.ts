import { gql } from "@apollo/client/core";

// === Fragments — each component declares its data requirements ===

export const POD_IDENTITY_FRAGMENT = gql`
  fragment PodIdentityFields on PodIdentity {
    hostname
    namespace
    serviceAccount
    nodeName
    podName
    podIp
  }
`;

export const SECURITY_FINDING_FRAGMENT = gql`
  fragment SecurityFindingFields on SecurityFinding {
    id
    title
    severity
    category
    description
    evidence
    remediation
  }
`;

export const SECURITY_SUMMARY_FRAGMENT = gql`
  fragment SecuritySummaryFields on SecuritySummary {
    critical
    high
    medium
    low
    info
    total
    score
  }
`;

export const SECURITY_REPORT_FRAGMENT = gql`
  fragment SecurityReportFields on SecurityReport {
    findings {
      ...SecurityFindingFields
    }
    summary {
      ...SecuritySummaryFields
    }
    identity {
      ...PodIdentityFields
    }
    timestamp
  }
  ${SECURITY_FINDING_FRAGMENT}
  ${SECURITY_SUMMARY_FRAGMENT}
  ${POD_IDENTITY_FRAGMENT}
`;

export const NETWORK_NODE_FRAGMENT = gql`
  fragment NetworkNodeFields on NetworkNode {
    name
    host
    port
    serviceType
    serviceTypeLabel
    reachable
    tls
    latencyMs
    httpStatus
    serverHeader
  }
`;

export const NETWORK_MAP_FRAGMENT = gql`
  fragment NetworkMapFields on NetworkMap {
    source {
      ...PodIdentityFields
    }
    nodes {
      ...NetworkNodeFields
    }
    totalServices
    reachable
    unreachable
    timestamp
  }
  ${POD_IDENTITY_FRAGMENT}
  ${NETWORK_NODE_FRAGMENT}
`;

export const SERVICE_TYPE_RESULT_FRAGMENT = gql`
  fragment ServiceTypeResultFields on ServiceTypeResult {
    name
    host
    port
    serviceType
    serviceTypeLabel
    confidence
    evidence
    tls
    reachable
    latencyMs
    httpStatus
    serverHeader
  }
`;

export const PROTOCOL_SUMMARY_FRAGMENT = gql`
  fragment ProtocolSummaryFields on ProtocolSummary {
    rest
    graphql
    grpc
    websocket
    database
    messageQueue
    staticFiles
    unknown
  }
`;

export const ASSESSMENT_SUMMARY_FRAGMENT = gql`
  fragment AssessmentSummaryFields on AssessmentSummary {
    totalServices
    reachableServices
    serviceTypeBreakdown
    securityScore
    tlsCoveragePercent
    protocols {
      ...ProtocolSummaryFields
    }
  }
  ${PROTOCOL_SUMMARY_FRAGMENT}
`;

// === Main query — composes all fragments ===

export const GET_REPORT = gql`
  query GetReport {
    report {
      id
      version
      timestamp
      durationMs
      source {
        ...PodIdentityFields
      }
      networkMap {
        ...NetworkMapFields
      }
      security {
        ...SecurityReportFields
      }
      serviceTypes {
        ...ServiceTypeResultFields
      }
      summary {
        ...AssessmentSummaryFields
      }
    }
  }
  ${POD_IDENTITY_FRAGMENT}
  ${NETWORK_MAP_FRAGMENT}
  ${SECURITY_REPORT_FRAGMENT}
  ${SERVICE_TYPE_RESULT_FRAGMENT}
  ${ASSESSMENT_SUMMARY_FRAGMENT}
`;
