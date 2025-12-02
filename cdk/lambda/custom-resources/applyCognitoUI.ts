import { CloudFormationCustomResourceEvent } from 'aws-lambda';
import { CognitoIdentityProviderClient, SetUICustomizationCommand } from '@aws-sdk/client-cognito-identity-provider';
import * as https from 'https';
import * as url from 'url';
import { readFileSync } from 'fs';
import { join } from 'path';

const cognito = new CognitoIdentityProviderClient({});

const ADMIN_USER_POOL_ID = process.env.ADMIN_USER_POOL_ID!;
const ADMIN_CLIENT_ID = process.env.ADMIN_CLIENT_ID!;
const MEMBER_USER_POOL_ID = process.env.MEMBER_USER_POOL_ID!;
const MEMBER_CLIENT_ID = process.env.MEMBER_CLIENT_ID!;

/**
 * Send response to CloudFormation custom resource
 */
async function sendResponse(
  event: CloudFormationCustomResourceEvent,
  status: 'SUCCESS' | 'FAILED',
  data?: any,
  physicalResourceId?: string,
  reason?: string
): Promise<void> {
  const responseBody = JSON.stringify({
    Status: status,
    Reason: reason || (status === 'SUCCESS' ? 'See CloudWatch logs' : 'Failed to apply Cognito UI customization'),
    PhysicalResourceId: physicalResourceId || event.RequestId,
    StackId: event.StackId,
    RequestId: event.RequestId,
    LogicalResourceId: event.LogicalResourceId,
    Data: data,
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
      console.error('Error sending response:', error);
      reject(error);
    });

    request.write(responseBody);
    request.end();
  });
}

/**
 * Apply UI customization to a Cognito user pool client
 */
async function applyUICustomization(
  userPoolId: string,
  clientId: string,
  imageBytes: Buffer,
  css: string
): Promise<void> {
  await cognito.send(new SetUICustomizationCommand({
    UserPoolId: userPoolId,
    ClientId: clientId,
    ImageFile: imageBytes,
    CSS: css,
  }));
}

export const handler = async (event: CloudFormationCustomResourceEvent): Promise<void> => {
  try {
    const physicalId = ('PhysicalResourceId' in event)
      ? (event as any).PhysicalResourceId
      : event.RequestId;

    if (event.RequestType === 'Delete') {
      await sendResponse(event, 'SUCCESS', {}, physicalId);
      return;
    }

    if (event.RequestType === 'Create' || event.RequestType === 'Update') {
      // Read logo and CSS from bundled assets
      const logoPath = join(__dirname, 'logo.jpg');
      const cssPath = join(__dirname, 'cognito-ui.css');

      const logoBytes = readFileSync(logoPath);
      const css = readFileSync(cssPath, 'utf-8');

      // Apply to admin user pool
      await applyUICustomization(ADMIN_USER_POOL_ID, ADMIN_CLIENT_ID, logoBytes, css);

      // Apply to member user pool
      await applyUICustomization(MEMBER_USER_POOL_ID, MEMBER_CLIENT_ID, logoBytes, css);

      await sendResponse(event, 'SUCCESS', {
        message: 'UI customization applied to both user pools',
      });
      return;
    }

    await sendResponse(event, 'SUCCESS', {});
  } catch (error) {
    console.error('Error applying Cognito UI customization:', error);
    const errorPhysicalId = ('PhysicalResourceId' in event)
      ? (event as any).PhysicalResourceId
      : event.RequestId;
    await sendResponse(event, 'FAILED', {}, errorPhysicalId, String(error));
  }
};
