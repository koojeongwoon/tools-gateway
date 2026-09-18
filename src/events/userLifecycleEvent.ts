import { z } from "zod";

const profileSchema = z.object({
  email: z.email(),
  name: z.string().min(1),
}).strict();

export const userLifecycleEventSchema = z.object({
  schema: z.literal("iam.user.v1"),
  eventId: z.string().min(1),
  eventType: z.enum([
    "USER_CREATED",
    "USER_UPDATED",
    "USER_DISABLED",
    "USER_REENABLED",
    "USER_DELETED",
  ]),
  occurredAt: z.iso.datetime({ offset: true }),
  issuer: z.url(),
  tenantId: z.string().min(1),
  subjectId: z.string().min(1),
  userVersion: z.number().int().positive(),
  profile: profileSchema.optional(),
}).strict().superRefine((event, context) => {
  const carriesProfile = event.eventType === "USER_CREATED" || event.eventType === "USER_UPDATED";
  if (carriesProfile !== (event.profile !== undefined)) {
    context.addIssue({
      code: "custom",
      path: ["profile"],
      message: "profile is required only for create and update events",
    });
  }
});

export type UserLifecycleEvent = z.infer<typeof userLifecycleEventSchema>;

export function parseUserLifecycleEvent(input: unknown): UserLifecycleEvent {
  return userLifecycleEventSchema.parse(input);
}
