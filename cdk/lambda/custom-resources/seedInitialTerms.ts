import { CloudFormationCustomResourceEvent, CloudFormationCustomResourceResponse } from 'aws-lambda';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { DynamoDBClient, QueryCommand, PutItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall } from '@aws-sdk/util-dynamodb';
import * as https from 'https';
import * as url from 'url';
import { readFileSync } from 'fs';
import { join } from 'path';

const s3 = new S3Client({});
const ddb = new DynamoDBClient({});

const TABLE_MEMBERSHIP_TERMS = process.env.TABLE_MEMBERSHIP_TERMS!;
const TERMS_BUCKET = process.env.TERMS_BUCKET!;

async function sendResponse(
  event: CloudFormationCustomResourceEvent,
  responseStatus: 'SUCCESS' | 'FAILED',
  responseData?: any,
  physicalResourceId?: string,
  reason?: string
): Promise<void> {
  const responseBody = JSON.stringify({
    Status: responseStatus,
    Reason: reason || `See CloudWatch Log Stream: ${process.env.AWS_LAMBDA_LOG_STREAM_NAME}`,
    PhysicalResourceId: physicalResourceId || event.RequestId,
    StackId: event.StackId,
    RequestId: event.RequestId,
    LogicalResourceId: event.LogicalResourceId,
    Data: responseData || {},
  });

  const parsedUrl = url.parse(event.ResponseURL);
  const options = {
    hostname: parsedUrl.hostname,
    port: 443,
    path: parsedUrl.path,
    method: 'PUT',
    headers: {
      'content-type': '',
      'content-length': responseBody.length,
    },
  };

  return new Promise((resolve, reject) => {
    const request = https.request(options, (response) => {
      resolve();
    });
    request.on('error', (error) => {
      console.error('sendResponse Error:', error);
      reject(error);
    });
    request.write(responseBody);
    request.end();
  });
}

export const handler = async (event: CloudFormationCustomResourceEvent): Promise<void> => {
  console.log('Event:', JSON.stringify(event, null, 2));

  try {
    const physicalId = ('PhysicalResourceId' in event)
      ? (event as any).PhysicalResourceId
      : event.RequestId;

    if (event.RequestType === 'Delete') {
      // Don't delete terms on stack deletion
      await sendResponse(event, 'SUCCESS', {}, physicalId);
      return;
    }

    if (event.RequestType === 'Create' || event.RequestType === 'Update') {
      // Check if there's already a current membership term
      const queryResult = await ddb.send(new QueryCommand({
        TableName: TABLE_MEMBERSHIP_TERMS,
        IndexName: 'current-index',
        KeyConditionExpression: 'is_current = :true',
        ExpressionAttributeValues: marshall({ ':true': 'true' }),
        Limit: 1
      }));

      if (queryResult.Items && queryResult.Items.length > 0) {
        console.log('Current membership terms already exist, skipping seed');
        await sendResponse(event, 'SUCCESS', { message: 'Terms already exist' });
        return;
      }

      // Read the initial terms file
      const termsText = readFileSync(join(__dirname, 'initial-terms.txt'), 'utf-8');

      // Upload to S3
      const s3Key = `terms/v1.0.txt`;
      await s3.send(new PutObjectCommand({
        Bucket: TERMS_BUCKET,
        Key: s3Key,
        Body: termsText,
        ContentType: 'text/plain',
      }));

      console.log(`Uploaded initial terms to s3://${TERMS_BUCKET}/${s3Key}`);

      // Create DynamoDB record
      const versionId = 'v1.0';
      const createdAt = new Date().toISOString();

      await ddb.send(new PutItemCommand({
        TableName: TABLE_MEMBERSHIP_TERMS,
        Item: marshall({
          version_id: versionId,
          created_at: createdAt,
          created_by: 'system',
          is_current: 'true',
          s3_key: s3Key,
          terms_text: termsText,
          summary: 'Initial membership terms - Declaration of Independence',
        }),
      }));

      console.log(`Created membership terms record version ${versionId}`);

      await sendResponse(event, 'SUCCESS', { version_id: versionId, s3_key: s3Key });
      return;
    }

    await sendResponse(event, 'SUCCESS', {});
  } catch (error) {
    console.error('Error seeding initial terms:', error);
    const errorPhysicalId = ('PhysicalResourceId' in event)
      ? (event as any).PhysicalResourceId
      : event.RequestId;
    await sendResponse(event, 'FAILED', {}, errorPhysicalId, String(error));
  }
};
