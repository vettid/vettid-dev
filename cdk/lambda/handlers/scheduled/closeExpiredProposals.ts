import { DynamoDBClient, ScanCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';

const ddb = new DynamoDBClient({});
const TABLE_PROPOSALS = process.env.TABLE_PROPOSALS!;

/**
 * Scheduled Lambda to close proposals that have passed their closes_at time
 * Triggered by EventBridge scheduled rule
 */
export const handler = async (): Promise<void> => {
  console.log('Starting closeExpiredProposals job');

  try {
    const now = new Date();

    // Scan for all active proposals
    const scanResult = await ddb.send(new ScanCommand({
      TableName: TABLE_PROPOSALS,
      FilterExpression: '#status = :status',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: marshall({
        ':status': 'active',
      }),
    }));

    if (!scanResult.Items || scanResult.Items.length === 0) {
      console.log('No active proposals found');
      return;
    }

    const proposals = scanResult.Items.map(item => unmarshall(item));
    console.log(`Found ${proposals.length} active proposals`);

    let closedCount = 0;

    // Update proposals that have expired
    for (const proposal of proposals) {
      const closesAt = new Date(proposal.closes_at);

      if (now > closesAt) {
        console.log(`Closing expired proposal: ${proposal.proposal_id} (${proposal.proposal_title})`);

        await ddb.send(new UpdateItemCommand({
          TableName: TABLE_PROPOSALS,
          Key: marshall({
            proposal_id: proposal.proposal_id,
          }),
          UpdateExpression: 'SET #status = :closed, closed_at = :closed_at',
          ExpressionAttributeNames: {
            '#status': 'status',
          },
          ExpressionAttributeValues: marshall({
            ':closed': 'closed',
            ':closed_at': now.toISOString(),
          }),
        }));

        closedCount++;
      }
    }

    console.log(`Closed ${closedCount} expired proposals`);
  } catch (error: any) {
    console.error('Error closing expired proposals:', error);
    throw error;
  }
};
