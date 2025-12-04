import * as fs from "fs";
import * as path from "path";
import {
  init,
  shutdown,
  checkVersion,
  isInitialized,
  Server,
  Login,
  Logout,
  Identity,
  Session,
  HttpMethod,
  NameIdFormat,
} from "../dist";

const fixturesDir = path.join(__dirname, "fixtures");

describe("lasso.js", () => {
  beforeAll(() => {
    init();
  });

  afterAll(() => {
    shutdown();
  });

  describe("Core functions", () => {
    test("checkVersion returns version string", () => {
      const version = checkVersion();
      expect(version).toMatch(/^\d+\.\d+\.\d+$/);
    });

    test("isInitialized returns true after init", () => {
      expect(isInitialized()).toBe(true);
    });
  });

  describe("Constants", () => {
    test("HttpMethod has expected values", () => {
      expect(HttpMethod.REDIRECT).toBeDefined();
      expect(HttpMethod.POST).toBeDefined();
      expect(typeof HttpMethod.REDIRECT).toBe("number");
    });

    test("NameIdFormat has expected values", () => {
      expect(NameIdFormat.EMAIL).toBe(
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
      );
      expect(NameIdFormat.PERSISTENT).toBe(
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
      );
      expect(NameIdFormat.TRANSIENT).toBe(
        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
      );
    });
  });

  describe("Identity", () => {
    test("can create new Identity", () => {
      const identity = new Identity();
      expect(identity).toBeDefined();
    });

    test("can dump and restore Identity", () => {
      const identity = new Identity();
      const dump = identity.dump();
      expect(dump).toBeDefined();
      expect(typeof dump).toBe("string");
    });
  });

  describe("Session", () => {
    test("can create new Session", () => {
      const session = new Session();
      expect(session).toBeDefined();
    });

    test("new Session is empty", () => {
      const session = new Session();
      expect(session.isEmpty).toBe(true);
    });

    test("can dump and restore Session", () => {
      const session = new Session();
      const dump = session.dump();
      expect(dump).toBeDefined();

      if (dump) {
        const restored = Session.fromDump(dump);
        expect(restored).toBeDefined();
        expect(restored.isEmpty).toBe(true);
      }
    });
  });

  describe("Server", () => {
    let idpMetadata: string;
    let idpKey: string;
    let idpCert: string;
    let spMetadata: string;

    beforeAll(() => {
      idpMetadata = fs.readFileSync(
        path.join(fixturesDir, "idp-metadata.xml"),
        "utf-8"
      );
      idpKey = fs.readFileSync(
        path.join(fixturesDir, "idp-key.pem"),
        "utf-8"
      );
      idpCert = fs.readFileSync(
        path.join(fixturesDir, "idp-cert.pem"),
        "utf-8"
      );
      spMetadata = fs.readFileSync(
        path.join(fixturesDir, "sp-metadata.xml"),
        "utf-8"
      );
    });

    test("can create Server from buffers", () => {
      const server = Server.fromBuffers(idpMetadata, idpKey, idpCert);
      expect(server).toBeDefined();
      expect(server.entityId).toBe("https://idp.example.com");
    });

    test("can add provider to Server", () => {
      const server = Server.fromBuffers(idpMetadata, idpKey, idpCert);
      server.addProviderFromBuffer("https://sp.example.com", spMetadata);

      const provider = server.getProvider("https://sp.example.com");
      expect(provider).toBeDefined();
      expect(provider?.entityId).toBe("https://sp.example.com");
    });

    test("can dump and restore Server", () => {
      const server = Server.fromBuffers(idpMetadata, idpKey, idpCert);
      const dump = server.dump();
      expect(dump).toBeDefined();
      expect(typeof dump).toBe("string");

      const restored = Server.fromDump(dump);
      expect(restored).toBeDefined();
      expect(restored.entityId).toBe("https://idp.example.com");
    });
  });

  describe("Login (IdP)", () => {
    let server: ReturnType<typeof Server.fromBuffers>;
    let spMetadata: string;

    beforeAll(() => {
      const idpMetadata = fs.readFileSync(
        path.join(fixturesDir, "idp-metadata.xml"),
        "utf-8"
      );
      const idpKey = fs.readFileSync(
        path.join(fixturesDir, "idp-key.pem"),
        "utf-8"
      );
      const idpCert = fs.readFileSync(
        path.join(fixturesDir, "idp-cert.pem"),
        "utf-8"
      );
      spMetadata = fs.readFileSync(
        path.join(fixturesDir, "sp-metadata.xml"),
        "utf-8"
      );

      server = Server.fromBuffers(idpMetadata, idpKey, idpCert);
      server.addProviderFromBuffer("https://sp.example.com", spMetadata);
    });

    test("can create Login from Server", () => {
      const login = new Login(server);
      expect(login).toBeDefined();
    });

    test("Login has null identity and session initially", () => {
      const login = new Login(server);
      expect(login.identity).toBeNull();
      expect(login.session).toBeNull();
    });

    test("can set relayState", () => {
      const login = new Login(server);
      login.relayState = "https://app.example.com/dashboard";
      expect(login.relayState).toBe("https://app.example.com/dashboard");
    });
  });

  describe("Logout", () => {
    let server: ReturnType<typeof Server.fromBuffers>;

    beforeAll(() => {
      const idpMetadata = fs.readFileSync(
        path.join(fixturesDir, "idp-metadata.xml"),
        "utf-8"
      );
      const idpKey = fs.readFileSync(
        path.join(fixturesDir, "idp-key.pem"),
        "utf-8"
      );
      const idpCert = fs.readFileSync(
        path.join(fixturesDir, "idp-cert.pem"),
        "utf-8"
      );

      server = Server.fromBuffers(idpMetadata, idpKey, idpCert);
    });

    test("can create Logout from Server", () => {
      const logout = new Logout(server);
      expect(logout).toBeDefined();
    });

    test("Logout has null identity and session initially", () => {
      const logout = new Logout(server);
      expect(logout.identity).toBeNull();
      expect(logout.session).toBeNull();
    });
  });
});
