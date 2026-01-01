/**
 * AWS SDK client exports
 * Provides singleton instances of commonly used AWS clients
 */

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { SESClient } from '@aws-sdk/client-ses';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';

// Singleton clients - reused across Lambda invocations
let dynamoClient: DynamoDBClient | null = null;
let docClient: DynamoDBDocumentClient | null = null;
let sesClient: SESClient | null = null;
let cognitoClient: CognitoIdentityProviderClient | null = null;

export function getDynamoDBClient(): DynamoDBClient {
  if (!dynamoClient) {
    dynamoClient = new DynamoDBClient({});
  }
  return dynamoClient;
}

export function getDynamoDBDocumentClient(): DynamoDBDocumentClient {
  if (!docClient) {
    docClient = DynamoDBDocumentClient.from(getDynamoDBClient(), {
      marshallOptions: {
        removeUndefinedValues: true,
      },
    });
  }
  return docClient;
}

export function getSESClient(): SESClient {
  if (!sesClient) {
    sesClient = new SESClient({});
  }
  return sesClient;
}

export function getCognitoClient(): CognitoIdentityProviderClient {
  if (!cognitoClient) {
    cognitoClient = new CognitoIdentityProviderClient({});
  }
  return cognitoClient;
}
