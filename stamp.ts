import * as URLSafeBase64 from "urlsafe-base64";

/**
 * Enumeration of supported DNS stamp protocols.
 */
enum Protocol {
	DNSCrypt = 0x01,
	DOH,
	DOT,
	Plain,
	ODOH,
	AnonymizedRelay = 0x81,
	ODOHRelay = 0x85,
}

/**
 * Namespace containing DNS stamp related functionality.
 * DNS stamps are compact strings containing all the necessary information to connect to DNS servers.
 */
export namespace DNSStamp {
	/**
	 * Represents the properties of a DNS stamp.
	 */
	export class Properties {
		/**
		 * Indicates whether DNSSEC validation is required.
		 * @default true
		 */
		dnssec = true;

		/**
		 * Indicates whether the server promises not to log user queries.
		 * @default true
		 */
		nolog = true;

		/**
		 * Indicates whether the server promises not to filter any results.
		 * @default true
		 */
		nofilter = true;

		/**
		 * Creates a new Properties instance.
		 * @param init - Optional partial properties to initialize with
		 */
		constructor(init?: Partial<Properties>) {
			Object.assign(this, init);
		}

		/**
		 * Converts the properties to a number representation.
		 * @returns A number representing the binary state of all properties
		 */
		toNumber(): number {
			return (
				((this.dnssec ? 1 : 0) << 0) |
				((this.nolog ? 1 : 0) << 1) |
				((this.nofilter ? 1 : 0) << 2)
			);
		}
	}

	/**
	 * Base interface for all DNS stamps.
	 */
	export interface Stamp {
		/**
		 * Converts the stamp to its string representation.
		 * @returns The string representation of the stamp
		 */
		toString(): string;
	}

	/**
	 * Represents a DNSCrypt stamp.
	 */
	export class DNSCrypt implements Stamp {
		/**
		 * The properties of the DNSCrypt stamp.
		 */
		props = new Properties();

		/**
		 * The DNSCrypt provider's Ed25519 public key as 32 raw bytes.
		 */
		pk = "";
		
		/**
		 * The DNSCrypt provider name.
		 */
		providerName = "";

		/**
		 * Creates a new DNSCrypt stamp.
		 * @param addr - The IP address, as a string, with optional port number (if the server is not accessible over the standard port for the protocol, i.e. port 443). IPv6 addresses must be in square brackets, eg. "[fe80::6d6d:f72c:3ad:60b8]". Scopes are permitted.
		 * @param init - Optional partial initialization parameters
		 */
		constructor(
			readonly addr: string,
			init?: Partial<DNSCrypt>,
		) {
			Object.assign(this, init);
		}

		/**
         * Converts the DNSCrypt stamp to its string representation.
         * @returns The string representation of the DNSCrypt stamp
         */
		public toString() {
			const props = this.props.toNumber();
			const addr = this.addr.split("").map((c) => c.charCodeAt(0));

			const v = [
				Protocol.DNSCrypt,
				props,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
			];
			v.push(addr.length, ...addr);
			const pk = Buffer.from(this.pk.replace(/[: \t]/g, ""), "hex");
			v.push(pk.length, ...pk);
			const providerName = this.providerName
				.split("")
				.map((c) => c.charCodeAt(0));
			v.push(providerName.length, ...providerName);
			return `sdns://${URLSafeBase64.encode(Buffer.from(v))}`;
		}
	}

	/**
	 * Represents an Oblivious DNS over HTTPS stamp.
	 */
	export class ODOH implements Stamp {
		/**
		 * The properties of the ODOH stamp.
		 */
		props = new Properties();

		/**
		 * The server hostname which will be used as SNI name.
		 * Characters outside URL-permitted range should be sent as-is.
		 * (neither URL-encoded nor punycode).
		 * @default ""
		 */
		hostName = "";

		/**
		 * The absolute URI path (e.g., /.well-known/dns-query).
		 */
		path = "";

		/**
		 * Creates a new Oblivious DNS over HTTPS (ODoH) stamp.
		 * @param init - Optional partial initialization parameters
		 */
		constructor(init?: Partial<ODOH>) {
			Object.assign(this, init);
		}

		/**
         * Converts the ODOH stamp to its string representation.
         * @returns The string representation of the ODOH stamp
         */
		public toString(): string {
			const props = this.props.toNumber();

			const v = [
				Protocol.ODOH,
				props,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
			];
			const hostName = this.hostName.split("").map((c) => c.charCodeAt(0));
			v.push(hostName.length, ...hostName);
			const path = this.path.split("").map((c) => c.charCodeAt(0));
			v.push(path.length, ...path);
			return `sdns://${URLSafeBase64.encode(Buffer.from(v))}`;
		}
	}

	/**
	 * Represents a DNS over HTTPS stamp.
	 */
	export class DOH extends ODOH {
		/**
		 * SHA256 digest of one of the TBS certificate(s) in the validation chain.
		 * This is typically the certificate used to sign the resolver's certificate.
		 * Multiple hashes can be provided for rotation support.
		 */
		hash = "";

		/**
		 * Creates a new DNS over HTTPS (DoH) stamp.
		 * If the 'addr' parameter is an empty string or just a port number, the host name will be resolved to an IP address using another resolver.
		 * @param addr - Either Server IP address or port with colon prefix
		 * @param init - Optional partial initialization parameters
		 */
		constructor(
			readonly addr: string,
			init?: Partial<DOH>,
		) {
			super(init);
			Object.assign(this, init);
		}

		/**
         * Converts the DOH stamp to its string representation.
         * @returns The string representation of the DOH stamp
         */
		public toString(): string {
			return this._toString(Protocol.DOH);
		}

		/**
         * Converts the stamp to its string representation with the specified protocol.
         * @param protocol - The protocol to use for the string representation
         * @returns The string representation of the stamp
         */
		_toString(protocol: Protocol): string {
			const props = this.props.toNumber();
			const addr = this.addr.split("").map((c) => c.charCodeAt(0));

			const v = [protocol, props, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
			v.push(addr.length, ...addr);
			const hash = Buffer.from(this.hash.replace(/[: \t]/g, ""), "hex");
			v.push(hash.length, ...hash);
			const hostName = this.hostName.split("").map((c) => c.charCodeAt(0));
			v.push(hostName.length, ...hostName);
			const path = this.path.split("").map((c) => c.charCodeAt(0));
			v.push(path.length, ...path);
			return `sdns://${URLSafeBase64.encode(Buffer.from(v))}`;
		}
	}

	/**
	 * Represents a DNS over TLS stamp.
	 */
	export class DOT implements Stamp {
		/**
		 * The properties of the DOT stamp.
		 */
		props = new Properties();

		/**
		 * The server hostname used as SNI name.
		 */
		hostName = "";

		/**
		 * SHA256 digest of TBS certificate in the validation chain.
		 * Multiple hashes can be provided for rotation support.
		 */
		hash = "";

		/**
		 * Creates a new DNS over TLS (DoT) stamp.
		 * If the 'addr' parameter is an empty string or just a port number, the host name will be resolved to an IP address using another resolver.
		 * @param addr - Server IP address. IPv6 addresses must be in square brackets, eg. "[fe80::6d6d:f72c:3ad:60b8]". Scopes are permitted.
		 * @param init - Optional partial initialization parameters
		 */
		constructor(
			readonly addr: string,
			init?: Partial<DOT>,
		) {
			Object.assign(this, init);
		}

		/**
         * Converts the DOT stamp to its string representation.
         * @returns The string representation of the DOT stamp
         */
		public toString(): string {
			const props = this.props.toNumber();
			const addr = this.addr.split("").map((c) => c.charCodeAt(0));

			const v = [Protocol.DOT, props, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
			v.push(addr.length, ...addr);
			const hash = Buffer.from(this.hash.replace(/[: \t]/g, ""), "hex");
			v.push(hash.length, ...hash);
			const hostName = this.hostName.split("").map((c) => c.charCodeAt(0));
			v.push(hostName.length, ...hostName);
			return `sdns://${URLSafeBase64.encode(Buffer.from(v))}`;
		}
	}

	/**
	 * Represents a plain DNS stamp.
	 */
	export class Plain implements Stamp {
		/**
		 * The properties of the plain DNS stamp.
		 */
		props = new Properties();

		/**
		 * Creates a new Plain DNS stamp.
		 * If the 'addr' parameter is an empty string or just a port number, the host name will be resolved to an IP address using another resolver.
		 * @param addr - Server IP address or port number. IPv6 addresses must be in square brackets, eg. "[fe80::6d6d:f72c:3ad:60b8]". Scopes are permitted.
		 * @param init - Optional partial initialization parameters
		 */
		constructor(
			readonly addr: string,
			init?: Partial<Plain>,
		) {
			Object.assign(this, init);
		}

		/**
         * Converts the Plain stamp to its string representation.
         * @returns The string representation of the Plain stamp
         */
		public toString(): string {
			const props = this.props.toNumber();
			const addr = this.addr.split("").map((c) => c.charCodeAt(0));

			const v = [
				Protocol.Plain,
				props,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
			];
			v.push(addr.length, ...addr);
			return `sdns://${URLSafeBase64.encode(Buffer.from(v))}`;
		}
	}

	/**
	 * Represents an anonymized DNS relay stamp.
	 */
	export class AnonymizedRelay implements Stamp {
		/**
		 * The relay server address.
		 */
		addr: string;

		/**
		 * Creates a new AnonymizedRelay DNS stamp.
		 * If the 'addr' parameter is an empty string or just a port number, the host name will be resolved to an IP address using another resolver.
		 * @param addr - Server IP address or port number. IPv6 addresses must be in square brackets, eg. "[fe80::6d6d:f72c:3ad:60b8]". Scopes are permitted.
		 */
		constructor(addr: string) {
			this.addr = addr;
		}

		/**
         * Converts the Anonymized Relay stamp to its string representation.
         * @returns The string representation of the Anonymized Relay stamp
         */
		public toString(): string {
			const addr = this.addr.split("").map((c) => c.charCodeAt(0));

			const v = [Protocol.AnonymizedRelay];
			v.push(addr.length, ...addr);
			return `sdns://${URLSafeBase64.encode(Buffer.from(v))}`;
		}
	}

	/**
	 * Represents an Oblivious DNS over HTTPS relay stamp.
	 */
	export class ODOHRelay extends DOH {
		public toString(): string {
			return this._toString(Protocol.ODOHRelay);
		}
	}

	/**
	 * Parses a DNS stamp string into its corresponding stamp object.
	 * @param stamp - The DNS stamp string to parse (must start with "sdns://")
	 * @returns The parsed stamp object
	 * @throws Error if the stamp is invalid or the protocol is unsupported
	 */
	export function parse(stamp: string): Stamp {
		if (!stamp.startsWith("sdns://")) {
			throw new Error("invalid scheme");
		}
		const bin = URLSafeBase64.decode(stamp.substr(7));
		const type = bin[0];
		if (type === Protocol.AnonymizedRelay) {
			const addrLen = bin[1];
			const addr = bin.slice(2, 2 + addrLen).toString("utf-8");
			return new AnonymizedRelay(addr);
		}
		const props = new Properties({
			dnssec: !!((bin[1] >> 0) & 1),
			nolog: !!((bin[1] >> 1) & 1),
			nofilter: !!((bin[1] >> 2) & 1),
		});
		let i = 9;
		const addrLen = bin[i++];
		const addr = bin.slice(i, i + addrLen).toString("utf-8");
		i += addrLen;
		switch (type) {
			case Protocol.DNSCrypt: {
				const pkLen = bin[i++];
				const pk = bin.slice(i, i + pkLen).toString("hex");
				i += pkLen;
				const providerNameLen = bin[i++];
				const providerName = bin
					.slice(i, i + providerNameLen)
					.toString("utf-8");
				return new DNSCrypt(addr, { props, pk, providerName });
			}
			case Protocol.DOH:
			case Protocol.ODOHRelay: {
				const hashLen = bin[i++];
				const hash = bin.slice(i, i + hashLen).toString("hex");
				i += hashLen;
				const hostNameLen = bin[i++];
				const hostName = bin.slice(i, i + hostNameLen).toString("utf-8");
				i += hostNameLen;
				const pathLen = bin[i++];
				const path = bin.slice(i, i + pathLen).toString("utf-8");
				if (type === Protocol.DOH) {
					return new DOH(addr, { props, hash, hostName, path });
				}
				return new ODOHRelay(addr, { props, hash, hostName, path });
			}
			case Protocol.DOT: {
				const hashLen = bin[i++];
				const hash = bin.slice(i, i + hashLen).toString("hex");
				i += hashLen;
				const hostNameLen = bin[i++];
				const hostName = bin.slice(i, i + hostNameLen).toString("utf-8");
				i += hostNameLen;
				return new DOT(addr, { props, hash, hostName });
			}
			case Protocol.Plain: {
				return new Plain(addr, { props });
			}
			case Protocol.ODOH: {
				const pathLen = bin[i++];
				const path = bin.slice(i, i + pathLen).toString("utf-8");
				return new ODOH({ props, hostName: addr, path });
			}
		}

		throw new Error(`unsupported protocol: ${bin[0]}`);
	}
}
