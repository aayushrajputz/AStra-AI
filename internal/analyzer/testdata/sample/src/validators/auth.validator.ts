export const loginSchema = z.object({
  body: z.object({
    email: z.string(),
    totpCode: z.string(),
  }),
});
