# VettID Stack Refactoring Plan

## Goal
Split the monolithic VettIDStack (500 resources) into 4 separate stacks to overcome AWS CloudFormation's 500 resource limit and prepare for future growth.

## Stack Architecture

### 1. VettID-Infrastructure Stack (~200 resources)
**Purpose:** Foundation resources that other stacks depend on

**Resources:**
- **CloudFront Functions:** wwwRedirectFn, htmlRewriteFn, securityHeadersFn
- **ACM Certificate:** VettIdCert2025
- **S3 Buckets:** CloudFrontLogBucket, SiteBucket, MembershipTermsBucket
- **WAF:** WebAcl
- **CloudFront Distributions:** RootDist, WwwDist, AdminDist
- **Route 53 Records:** All A and AAAA records
- **Glue:** LogsDatabase, LogsTable
- **DynamoDB Tables:** All 16 tables
  - invites, registrations, audit, waitlist, magicLinkTokens
  - membershipTerms, subscriptions, proposals, votes, subscriptionTypes
  - credentials, credentialKeys, transactionKeys, ledgerAuthTokens
  - actionTokens, enrollmentSessions
- **Cognito:**
  - Lambda triggers (defineAuthChallenge, createAuthChallenge, verifyAuthChallenge, preTokenGeneration)
  - User Pools (MemberUserPool, AdminUserPool)
  - User Pool Domains
  - User Pool Groups
  - App Clients (AdminWebClient, MemberWebClient)
  - Custom UI attachments

**Exports:**
- All table names
- All table ARNs
- Bucket names and ARNs
- User Pool IDs
- App Client IDs
- Cognito Domain URLs
- Distribution IDs
- API URL (from Core stack - circular, handle carefully)

---

### 2. VettID-Core Stack (~150 resources)
**Purpose:** Core VettID services (registration, membership, subscriptions)

**Depends On:** Infrastructure Stack

**Lambdas:**
- **Public:**
  - submitRegistration
  - submitWaitlist
- **Stream Processors:**
  - registrationStreamFn
  - proposalStreamFn
- **Member/Account:**
  - changePassword
  - cancelAccount
  - enablePin, disablePin, updatePin, getPinStatus
  - getEmailPreferences, updateEmailPreferences
  - requestMembership, getMembershipStatus, getMembershipTerms
  - createSubscription, getSubscriptionStatus, cancelSubscription
  - listEnabledSubscriptionTypes
  - submitVote, getVotingHistory
  - getActiveProposals, getMemberProposalVoteCounts

**API Gateway:**
- HttpApi
- JWT Authorizer (from Infrastructure Cognito)
- **Routes:**
  - POST /register
  - POST /waitlist
  - POST /account/change-password
  - POST /account/cancel
  - GET/POST/PUT /account/security/pin/*
  - GET/PUT /account/email-preferences
  - POST /account/membership/request
  - GET /account/membership/status
  - GET /account/membership/terms
  - POST /account/subscriptions
  - GET /account/subscriptions/status
  - DELETE /account/subscriptions
  - GET /account/subscription-types
  - POST /account/votes
  - GET /account/votes/history
  - GET /account/proposals
  - GET /account/proposals/{id}/vote-counts

**Event Sources:**
- DynamoDB Streams for registrations table
- DynamoDB Streams for proposals table

**Exports:**
- API Gateway URL (for Infrastructure and other stacks)
- API Gateway ID

---

### 3. VettID-Admin Stack (~100 resources)
**Purpose:** Admin functionality, proposal management, voting

**Depends On:** Infrastructure Stack, Core Stack (for API Gateway)

**Lambdas:**
- **Registration Management:**
  - listRegistrations
  - approveRegistration
  - rejectRegistration
- **Invite Management:**
  - createInvite
  - listInvites
  - expireInvite
  - deleteInvite
- **User Management:**
  - disableUser, enableUser
  - deleteUser, permanentlyDeleteUser
- **Admin Management:**
  - listAdmins
  - addAdmin, removeAdmin
  - disableAdmin, enableAdmin
  - updateAdminType
  - resetAdminPassword
- **Membership Management:**
  - listMembershipRequests
  - approveMembership
  - denyMembership
  - createMembershipTerms
  - getCurrentMembershipTerms
  - listMembershipTerms
- **Proposal Management:**
  - createProposal
  - listProposals
  - suspendProposal
  - getProposalResults
  - getAllProposals
  - getProposalVoteCounts
- **Subscription Management:**
  - listSubscriptions
  - extendSubscription
  - reactivateSubscription
  - createSubscriptionType
  - listSubscriptionTypes
  - enableSubscriptionType
  - disableSubscriptionType
- **Waitlist Management:**
  - listWaitlist
  - sendWaitlistInvites
  - deleteWaitlistEntries
- **Scheduled Tasks:**
  - cleanupExpiredAccounts
  - closeExpiredProposals
  - checkSubscriptionExpiry

**API Routes:** (Added to Core Stack's API Gateway)
- All /admin/* routes

**EventBridge Rules:**
- Daily cleanup rule
- Hourly proposal close rule
- Daily subscription expiry check

---

### 4. VettID-Vault Stack (~50 resources)
**Purpose:** Vault enrollment and authentication services

**Depends On:** Infrastructure Stack, Core Stack (for API Gateway)

**Lambdas:**
- enrollStart
- enrollSetPassword
- enrollFinalize
- actionRequest
- authExecute

**API Routes:** (Added to Core Stack's API Gateway)
- POST /vault/enroll/start
- POST /vault/enroll/set-password
- POST /vault/enroll/finalize
- POST /vault/action/request
- POST /vault/auth/execute

---

## Migration Strategy

1. **Create Infrastructure Stack**
   - Extract all foundation resources
   - Add CfnOutputs for sharing

2. **Create Core Stack**
   - Import infrastructure resources
   - Create API Gateway
   - Add core Lambda functions and routes

3. **Create Admin Stack**
   - Import infrastructure and core resources
   - Add admin Lambda functions
   - Add routes to Core's API Gateway

4. **Create Vault Stack**
   - Import infrastructure and core resources
   - Add vault Lambda functions
   - Add routes to Core's API Gateway

5. **Update app.ts**
   - Instantiate all 4 stacks in order
   - Pass dependencies

6. **Deploy**
   - Deploy all stacks together initially
   - Future deploys can be independent

---

## Resource Sharing Approach

**Use CfnOutput + Fn::ImportValue:**
```typescript
// In Infrastructure Stack
new cdk.CfnOutput(this, 'RegistrationsTableName', {
  value: this.registrationsTable.tableName,
  exportName: 'VettID-RegistrationsTableName'
});

// In Core/Admin/Vault Stack
const tableName = cdk.Fn.importValue('VettID-RegistrationsTableName');
```

**Or use props passed via constructor:**
```typescript
// In app.ts
const infra = new InfrastructureStack(app, 'VettID-Infrastructure');
const core = new CoreStack(app, 'VettID-Core', {
  tables: infra.tables,
  userPools: infra.userPools,
  // ...
});
```

We'll use **constructor props** as it's more type-safe and flexible.
