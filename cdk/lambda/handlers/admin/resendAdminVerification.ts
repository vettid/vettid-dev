import { APIGatewayProxyHandlerV2 } from "aws-lambda";
import { ok, badRequest, putAudit, requireAdminGroup, validateOrigin, checkRateLimit, hashIdentifier, tooManyRequests, getAdminEmail, internalError, ddb } from "../../common/util";
import { SESClient, VerifyEmailIdentityCommand, GetIdentityVerificationAttributesCommand } from "@aws-sdk/client-ses";
import { GetItemCommand } from "@aws-sdk/client-dynamodb";
import { marshall } from "@aws-sdk/util-dynamodb";

const ses = new SESClient({});
const PENDING_ADMINS_TABLE = process.env.PENDING_ADMINS_TABLE!;

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  const requestOrigin = event.headers?.origin || event.headers?.Origin;

  // Validate admin group membership
  const authError = requireAdminGroup(event, requestOrigin);
  if (authError) return authError;

  // CSRF protection
  const csrfError = validateOrigin(event);
  if (csrfError) return csrfError;

  // Rate limiting: Max 5 resends per email per hour
  const email = event.pathParameters?.email;
  if (!email) {
    return badRequest("Email is required", requestOrigin);
  }

  const decodedEmail = decodeURIComponent(email).toLowerCase();
  const emailHash = hashIdentifier(decodedEmail);
  const isAllowed = await checkRateLimit(emailHash, 'resend_ses_verification', 5, 60);
  if (!isAllowed) {
    return tooManyRequests("Too many verification resend requests. Please try again later.", requestOrigin);
  }

  const requestedBy = getAdminEmail(event);

  try {
    // Verify the pending admin exists
    const pendingResult = await ddb.send(new GetItemCommand({
      TableName: PENDING_ADMINS_TABLE,
      Key: marshall({ email: decodedEmail })
    }));

    if (!pendingResult.Item) {
      return badRequest("No pending invitation found for this email", requestOrigin);
    }

    // Check if already verified
    const verificationStatus = await ses.send(new GetIdentityVerificationAttributesCommand({
      Identities: [decodedEmail]
    }));

    const currentStatus = verificationStatus.VerificationAttributes?.[decodedEmail]?.VerificationStatus;

    if (currentStatus === 'Success') {
      return ok({
        message: "Email is already verified. You can now activate this admin account.",
        email: decodedEmail,
        ses_status: 'Success',
        already_verified: true
      }, requestOrigin);
    }

    // Resend verification email
    await ses.send(new VerifyEmailIdentityCommand({
      EmailAddress: decodedEmail
    }));

    await putAudit({
      type: "admin_verification_resent",
      email: decodedEmail,
      requested_by: requestedBy,
      previous_status: currentStatus || 'NotStarted',
    });

    return ok({
      message: "Verification email resent successfully.",
      email: decodedEmail,
      ses_status: 'Pending'
    }, requestOrigin);

  } catch (error: any) {
    console.error('Error resending verification:', error);
    return internalError('Failed to resend verification email', requestOrigin);
  }
};
