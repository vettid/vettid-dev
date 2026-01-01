import { PostAuthenticationTriggerEvent, PostAuthenticationTriggerHandler } from 'aws-lambda';
import { CognitoIdentityProviderClient, AdminUpdateUserAttributesCommand } from '@aws-sdk/client-cognito-identity-provider';

const cognito = new CognitoIdentityProviderClient({});

/**
 * Post Authentication Lambda Trigger
 *
 * Updates the user's custom:last_login_at attribute after each successful login.
 * This enables tracking of when users last logged in.
 */
export const handler: PostAuthenticationTriggerHandler = async (event: PostAuthenticationTriggerEvent) => {
  const { userPoolId, userName } = event;

  try {
    // Update the last_login_at custom attribute
    await cognito.send(new AdminUpdateUserAttributesCommand({
      UserPoolId: userPoolId,
      Username: userName,
      UserAttributes: [
        {
          Name: 'custom:last_login_at',
          Value: new Date().toISOString(),
        },
      ],
    }));

    console.log(`Updated last_login_at for user ${userName}`);
  } catch (error) {
    // Don't fail the login if we can't update the attribute
    console.error(`Failed to update last_login_at for user ${userName}:`, error);
  }

  // Always return the event to complete the authentication
  return event;
};
