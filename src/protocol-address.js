export class ProtocolAddress {
  constructor(name, deviceId) { this.name = name; this.deviceId = deviceId; }
  toString() { return `${this.name}.${this.deviceId}`; }
}