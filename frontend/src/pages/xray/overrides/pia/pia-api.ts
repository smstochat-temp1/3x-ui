import type { ZodType } from 'zod';

import { HttpUtil, Msg } from '@/utils';
import {
  PiaCatalogStatusSchema,
  PiaDependencySchema,
  PiaEgressSchema,
  PiaProfileSchema,
  PiaRegionSchema,
  PiaServerSchema,
  PiaStatusSchema,
} from '@/schemas/pia';

export type {
  PiaCatalogStatus,
  PiaDependency,
  PiaEgress,
  PiaProfile,
  PiaRegion,
  PiaServer,
  PiaStatus,
} from '@/schemas/pia';

const jsonHeaders = { 'Content-Type': 'application/json' };

export const piaSchemas = {
  status: PiaStatusSchema,
  profile: PiaProfileSchema,
  profiles: PiaProfileSchema.array(),
  egress: PiaEgressSchema,
  egresses: PiaEgressSchema.array(),
  catalog: PiaCatalogStatusSchema,
  regions: PiaRegionSchema.array(),
  servers: PiaServerSchema.array(),
  dependencies: PiaDependencySchema.array(),
};

export async function piaGet<T>(url: string, schema?: ZodType<T>) {
  const msg = await HttpUtil.get<T>(url, undefined, { silent: true });
  return parseMsg(msg, schema);
}

export async function piaPost<T>(url: string, body?: unknown, schema?: ZodType<T>) {
  const msg = await HttpUtil.post<T>(url, body, { silent: true, headers: jsonHeaders });
  return parseMsg(msg, schema);
}

export async function piaPatch<T>(url: string, body?: unknown, schema?: ZodType<T>) {
  const msg = await HttpUtil.patch<T>(url, body, { silent: true, headers: jsonHeaders });
  return parseMsg(msg, schema);
}

export async function piaDelete(url: string) {
  return HttpUtil.delete(url, { silent: true });
}

function parseMsg<T>(msg: Msg<T>, schema?: ZodType<T>): Msg<T> {
  if (!msg.success || schema == null || msg.obj == null) {
    return msg;
  }
  const parsed = schema.safeParse(msg.obj);
  if (!parsed.success) {
    return new Msg<T>(false, msg.msg || 'Malformed PIA response', null);
  }
  return new Msg<T>(true, msg.msg, parsed.data as T);
}
