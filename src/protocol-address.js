export class ProtocolAddress {
  constructor(name, deviceId) { this.name = name; this.deviceId = deviceId; }
  toString() { return `${this.name}.${this.deviceId}`; }
  static fromString(str) {
    const dot = str.lastIndexOf('.');
    return new ProtocolAddress(str.slice(0, dot), parseInt(str.slice(dot + 1), 10));
  }
}