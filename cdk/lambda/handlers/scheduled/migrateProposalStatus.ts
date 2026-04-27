import { DynamoDBClient, ScanCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';

const ddb = new DynamoDBClient({});
const TABLE_PROPOSALS = process.env.TABLE_PROPOSALS!;

// One-shot migration to align proposal status strings with the canonical
// vocabulary used by the vault parent's ListProposals filter and the Android
// app enum:
//
//   draft, upcoming, active, closed, cancelled
//
// Anything else (ended, finalized, published) gets rewritten to the closest
// canonical equivalent so closed proposals show up in the app and existing
// rows don't get stranded.
const STATUS_REWRITES: Record<string, string> = {
  ended: 'closed',
  finalized: 'closed',
  published: 'active', // a "published" proposal is one open for voting
};

export const handler = async (): Promise<void> => {
  console.log('Starting proposal status migration');
  let scanned = 0;
  let rewritten = 0;
  let lastEvaluated: any = undefined;

  do {
    const result: any = await ddb.send(new ScanCommand({
      TableName: TABLE_PROPOSALS,
      ExclusiveStartKey: lastEvaluated,
    }));

    for (const item of result.Items || []) {
      scanned++;
      const proposal = unmarshall(item);
      const oldStatus = String(proposal.status || '');
      const newStatus = STATUS_REWRITES[oldStatus];
      if (!newStatus) continue;

      console.log(`Rewriting ${proposal.proposal_id}: ${oldStatus} → ${newStatus}`);
      await ddb.send(new UpdateItemCommand({
        TableName: TABLE_PROPOSALS,
        Key: marshall({ proposal_id: proposal.proposal_id }),
        UpdateExpression: 'SET #s = :new',
        ConditionExpression: '#s = :old',
        ExpressionAttributeNames: { '#s': 'status' },
        ExpressionAttributeValues: marshall({
          ':new': newStatus,
          ':old': oldStatus,
        }),
      }));
      rewritten++;
    }

    lastEvaluated = result.LastEvaluatedKey;
  } while (lastEvaluated);

  console.log(`Migration complete: scanned=${scanned}, rewritten=${rewritten}`);
};
