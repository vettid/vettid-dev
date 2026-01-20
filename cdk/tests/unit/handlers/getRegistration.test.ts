/**
 * Unit tests for GET /profile/registration Lambda
 * Tests the getRegistration handler that returns user registration data.
 */

import { APIGatewayProxyEventV2, APIGatewayProxyStructuredResultV2 } from "aws-lambda";

// Mock DynamoDB client before importing handler
const mockSend = jest.fn();
jest.mock("@aws-sdk/client-dynamodb", () => ({
  DynamoDBClient: jest.fn(() => ({
    send: mockSend,
  })),
  QueryCommand: jest.fn((input: any) => ({ input })),
}));

// Mock environment variables
process.env.TABLE_REGISTRATIONS = "test-registrations-table";

// Import handler after mocks are set up
import { handler } from "../../../lambda/handlers/profile/getRegistration";

describe("GET /profile/registration", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  /**
   * Creates a mock API Gateway event with JWT claims
   */
  function createMockEvent(claims?: Record<string, string>): APIGatewayProxyEventV2 {
    const event: any = {
      version: "2.0",
      routeKey: "GET /profile/registration",
      rawPath: "/profile/registration",
      rawQueryString: "",
      headers: {
        origin: "https://app.vettid.com",
      },
      requestContext: {
        accountId: "123456789012",
        apiId: "api-id",
        domainName: "api.vettid.com",
        domainPrefix: "api",
        http: {
          method: "GET",
          path: "/profile/registration",
          protocol: "HTTP/1.1",
          sourceIp: "127.0.0.1",
          userAgent: "test",
        },
        requestId: "test-request-id",
        routeKey: "GET /profile/registration",
        stage: "test",
        time: new Date().toISOString(),
        timeEpoch: Date.now(),
      },
      isBase64Encoded: false,
    };

    // Add authorizer with JWT claims if provided
    if (claims) {
      event.requestContext.authorizer = {
        jwt: {
          claims: claims,
        },
      };
    }

    return event as APIGatewayProxyEventV2;
  }

  /**
   * Call handler and cast result to structured response
   */
  async function callHandler(event: APIGatewayProxyEventV2): Promise<APIGatewayProxyStructuredResultV2> {
    const result = await handler(event);
    return result as APIGatewayProxyStructuredResultV2;
  }

  describe("Success Cases", () => {
    test("returns registration data for authenticated user", async () => {
      // Arrange: Set up mock DynamoDB response
      mockSend.mockResolvedValueOnce({
        Items: [
          {
            email: { S: "test@example.com" },
            first_name: { S: "John" },
            last_name: { S: "Doe" },
            status: { S: "approved" },
          },
        ],
      });

      const event = createMockEvent({
        "custom:user_guid": "test-user-guid",
        email: "test@example.com",
      });

      // Act
      const result = await callHandler(event);

      // Assert
      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body!);
      expect(body.firstName).toBe("John");
      expect(body.lastName).toBe("Doe");
      expect(body.email).toBe("test@example.com");
    });

    test("returns registration with empty names if not set", async () => {
      mockSend.mockResolvedValueOnce({
        Items: [
          {
            email: { S: "test@example.com" },
            status: { S: "approved" },
          },
        ],
      });

      const event = createMockEvent({
        "custom:user_guid": "test-user-guid",
        email: "test@example.com",
      });

      const result = await callHandler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body!);
      expect(body.firstName).toBe("");
      expect(body.lastName).toBe("");
      expect(body.email).toBe("test@example.com");
    });

    test("uses claims email if registration email is missing", async () => {
      mockSend.mockResolvedValueOnce({
        Items: [
          {
            first_name: { S: "Jane" },
            last_name: { S: "Smith" },
            status: { S: "approved" },
          },
        ],
      });

      const event = createMockEvent({
        "custom:user_guid": "test-user-guid",
        email: "claims@example.com",
      });

      const result = await callHandler(event);

      expect(result.statusCode).toBe(200);
      const body = JSON.parse(result.body!);
      expect(body.email).toBe("claims@example.com");
    });
  });

  describe("Authentication Errors", () => {
    test("returns 400 when JWT claims are missing", async () => {
      const event = createMockEvent(undefined);

      const result = await callHandler(event);

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body!);
      expect(body.message).toContain("Invalid token");
    });

    test("returns 400 when user_guid is missing", async () => {
      const event = createMockEvent({
        email: "test@example.com",
        // missing user_guid
      });

      const result = await callHandler(event);

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body!);
      expect(body.message).toContain("Invalid token");
    });

    test("returns 400 when email is missing", async () => {
      const event = createMockEvent({
        "custom:user_guid": "test-user-guid",
        // missing email
      });

      const result = await callHandler(event);

      expect(result.statusCode).toBe(400);
      const body = JSON.parse(result.body!);
      expect(body.message).toContain("Invalid token");
    });
  });

  describe("Not Found Cases", () => {
    test("returns 404 when no registration found", async () => {
      mockSend.mockResolvedValueOnce({
        Items: [],
      });

      const event = createMockEvent({
        "custom:user_guid": "test-user-guid",
        email: "nonexistent@example.com",
      });

      const result = await callHandler(event);

      expect(result.statusCode).toBe(404);
      const body = JSON.parse(result.body!);
      expect(body.message).toContain("Registration not found");
    });

    test("returns 404 when Items is undefined", async () => {
      mockSend.mockResolvedValueOnce({
        // No Items field
      });

      const event = createMockEvent({
        "custom:user_guid": "test-user-guid",
        email: "test@example.com",
      });

      const result = await callHandler(event);

      expect(result.statusCode).toBe(404);
    });
  });

  describe("DynamoDB Query", () => {
    test("queries with correct table and index", async () => {
      mockSend.mockResolvedValueOnce({
        Items: [
          {
            email: { S: "test@example.com" },
            first_name: { S: "John" },
            last_name: { S: "Doe" },
            status: { S: "approved" },
          },
        ],
      });

      const event = createMockEvent({
        "custom:user_guid": "test-user-guid",
        email: "test@example.com",
      });

      await callHandler(event);

      // Verify the query was made with correct parameters
      expect(mockSend).toHaveBeenCalledTimes(1);
      const queryCommand = mockSend.mock.calls[0][0];
      expect(queryCommand.input.TableName).toBe("test-registrations-table");
      expect(queryCommand.input.IndexName).toBe("email-index");
      expect(queryCommand.input.KeyConditionExpression).toBe("email = :email");
      expect(queryCommand.input.ExpressionAttributeValues[":email"].S).toBe("test@example.com");
    });

    test("filters out deleted and rejected registrations", async () => {
      mockSend.mockResolvedValueOnce({
        Items: [
          {
            email: { S: "test@example.com" },
            first_name: { S: "John" },
            last_name: { S: "Doe" },
            status: { S: "approved" },
          },
        ],
      });

      const event = createMockEvent({
        "custom:user_guid": "test-user-guid",
        email: "test@example.com",
      });

      await callHandler(event);

      const queryCommand = mockSend.mock.calls[0][0];
      expect(queryCommand.input.FilterExpression).toContain("deleted");
      expect(queryCommand.input.FilterExpression).toContain("rejected");
    });
  });

  describe("Error Handling", () => {
    test("returns 500 on DynamoDB error", async () => {
      mockSend.mockRejectedValueOnce(new Error("DynamoDB connection error"));

      const event = createMockEvent({
        "custom:user_guid": "test-user-guid",
        email: "test@example.com",
      });

      const result = await callHandler(event);

      expect(result.statusCode).toBe(500);
      const body = JSON.parse(result.body!);
      expect(body.message).toBe("Failed to get registration");
    });
  });

  describe("CORS Headers", () => {
    test("includes CORS headers in response", async () => {
      mockSend.mockResolvedValueOnce({
        Items: [
          {
            email: { S: "test@example.com" },
            first_name: { S: "John" },
            last_name: { S: "Doe" },
            status: { S: "approved" },
          },
        ],
      });

      const event = createMockEvent({
        "custom:user_guid": "test-user-guid",
        email: "test@example.com",
      });
      event.headers.origin = "https://app.vettid.com";

      const result = await callHandler(event);

      expect(result.headers?.["Access-Control-Allow-Origin"]).toBeDefined();
    });
  });
});
