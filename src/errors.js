export class SignalError extends Error {
  constructor(message) { super(message); this.name = this.constructor.name; }
}
export class InvalidMessageTypeError extends SignalError {}
export class InvalidKeyError extends SignalError {}
export class NoSessionError extends SignalError {}
export class UntrustedIdentityKeyError extends SignalError {}
export class InvalidMessageLengthError extends SignalError {}