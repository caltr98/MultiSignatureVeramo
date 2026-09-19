import { DataSource } from 'typeorm'
import { Entities, migrations } from '@veramo/data-store'

export function demoConfig(databaseVariable = 'VERAMO_DB') {
  const secretKey = process.env.VERAMO_KMS_SECRET_KEY
  if (!secretKey || !/^[0-9a-f]{64}$/i.test(secretKey))
    throw new Error(
      'Set VERAMO_KMS_SECRET_KEY to a 32-byte hexadecimal key before starting the demo',
    )
  return {
    secretKey,
    rpcUrl: process.env.SEPOLIA_RPC_URL || 'http://127.0.0.1:8545',
    registry:
      process.env.VERAMO_DID_REGISTRY ||
      '0x03d5003bf0e79C5F5223588F347ebA39AfbC3818',
    database:
      process.env[databaseVariable] ||
      (databaseVariable === 'VERAMO_DB'
        ? 'database.sqlite'
        : 'database_eip712.sqlite'),
  }
}

export function demoDatabase(database: string) {
  return new DataSource({
    type: 'sqlite',
    database,
    synchronize: false,
    migrations,
    migrationsRun: true,
    logging: ['error', 'warn'],
    entities: Entities,
  }).initialize()
}
