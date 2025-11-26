import { PreTokenGenerationTriggerHandler } from 'aws-lambda';

export const handler: PreTokenGenerationTriggerHandler = async (event) => {
  // Add custom:admin_type to the ID token
  if (event.request.userAttributes['custom:admin_type']) {
    event.response.claimsOverrideDetails = {
      claimsToAddOrOverride: {
        'custom:admin_type': event.request.userAttributes['custom:admin_type'],
      },
    };
  }

  return event;
};
