import { z } from "zod";

export const userServiceAccessEventSchema = z.object({
  schema: z.literal("iam.user-service-access.v1"),
  eventId: z.string().min(1),
  eventType: z.enum([
    "USER_SERVICE_ENABLED",
    "USER_SERVICE_DISABLED",
    "USER_SERVICE_WITHDRAWN",
  ]),
  occurredAt: z.iso.datetime(),
  issuer: z.url(),
  tenantId: z.string().min(1),
  subjectId: z.string().min(1),
  clientId: z.string().min(1),
  accessVersion: z.number().int().positive(),
  status: z.enum(["ACTIVE", "DISABLED", "WITHDRAWN"]),
}).strict().superRefine((event, context) => {
  const expectedStatus = {
    USER_SERVICE_ENABLED: "ACTIVE",
    USER_SERVICE_DISABLED: "DISABLED",
    USER_SERVICE_WITHDRAWN: "WITHDRAWN",
  }[event.eventType];
  if (event.status !== expectedStatus) {
    context.addIssue({
      code: "custom",
      path: ["status"],
      message: `status ${event.status} does not match eventType ${event.eventType}`,
    });
  }
});

export type UserServiceAccessEvent = z.infer<typeof userServiceAccessEventSchema>;

export function parseUserServiceAccessEvent(input: unknown): UserServiceAccessEvent {
  return userServiceAccessEventSchema.parse(input);
}
