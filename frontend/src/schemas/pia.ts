import { z } from 'zod';

export const PiaStatusSchema = z.object({
  secretboxReady: z.boolean(),
  encryptionMode: z.string().optional(),
}).loose();
export type PiaStatus = z.infer<typeof PiaStatusSchema>;

export const PiaProfileSchema = z.object({
  uid: z.string(),
  name: z.string(),
  accountHint: z.string().optional(),
  hasToken: z.boolean().optional(),
  tokenExpiresAt: z.number().optional(),
  authStatus: z.string().optional(),
  enabled: z.boolean().optional(),
}).loose();
export type PiaProfile = z.infer<typeof PiaProfileSchema>;

export const PiaRegionSchema = z.object({
  id: z.string(),
  name: z.string(),
  countryCode: z.string(),
  serverCount: z.number().optional(),
}).loose();
export type PiaRegion = z.infer<typeof PiaRegionSchema>;

export const PiaServerSchema = z.object({
  hostname: z.string(),
  ip: z.string(),
}).loose();
export type PiaServer = z.infer<typeof PiaServerSchema>;

export const PiaEgressSchema = z.object({
  uid: z.string(),
  profileUid: z.string().optional(),
  name: z.string(),
  outboundTag: z.string(),
  regionId: z.string().optional(),
  regionName: z.string().optional(),
  serverHostname: z.string().optional(),
  status: z.string().optional(),
  enabled: z.boolean().optional(),
  lastErrorCode: z.string().optional(),
  lastErrorMessage: z.string().optional(),
  hasActiveBinding: z.boolean().optional(),
  ipv6Policy: z.string().optional(),
}).loose();
export type PiaEgress = z.infer<typeof PiaEgressSchema>;

export const PiaCatalogStatusSchema = z.object({
  fresh: z.boolean().optional(),
  fetchedAt: z.number().optional(),
  regionCount: z.number().optional(),
  serverCount: z.number().optional(),
  lastErrorCode: z.string().optional(),
  lastErrorMessage: z.string().optional(),
}).loose();
export type PiaCatalogStatus = z.infer<typeof PiaCatalogStatusSchema>;

export const PiaDependencySchema = z.object({
  kind: z.string(),
  label: z.string(),
  field: z.string(),
}).loose();
export type PiaDependency = z.infer<typeof PiaDependencySchema>;
