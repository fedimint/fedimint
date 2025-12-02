import { sdk } from '../sdk'
import { setBackend } from './setBackend'

export const actions = sdk.Actions.of().addAction(setBackend)
