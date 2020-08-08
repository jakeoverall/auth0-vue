import createAuth0Client from "@auth0/auth0-spa-js";
import { EventEmitter } from "./EventEmitter";

/** Define a default action to perform after authentication */
const DEFAULT_REDIRECT_CALLBACK = () =>
  window.history.replaceState({}, document.title, window.location.pathname);

/**
 @type {AuthPlugin}
 */
let instance;

class AuthPlugin extends EventEmitter {
  constructor(options = {}) {
    if (instance) { return instance }
    super()
    instance = this
    this.AUTH_EVENTS = {
      LOADING: "LOADING",
      LOADED: "LOADED",
      AUTHENTICATED: "AUTHENTICATED"
    }
    this.options = options
    this.options.onRedirectCallback = this.options.onRedirectCallback || DEFAULT_REDIRECT_CALLBACK
    this.loading = true
    this.isAuthenticated = false
    this.user = {}
    this.userInfo = {}
    this.identity = {}
    this.bearer = ""
    this.auth0Client = null
    this.popupOpen = false
    this.error = null
    this.created(options)
    return instance
  }

  /** Authenticates the user using a popup window */
  async loginWithPopup(o = {
    returnTo: window.location.origin
  }) {
    this.popupOpen = true;

    try {
      await this.auth0Client.loginWithPopup(o);
      this.user = await this.auth0Client.getUser();
      await this.getUserData();
      this.isAuthenticated = true;
    } catch (e) {
      // eslint-disable-next-line
      console.error(e);
    } finally {
      this.popupOpen = false;
    }

  }
  /** Handles the callback when logging in using a redirect */
  async handleRedirectCallback() {
    this.loading = true;
    try {
      await this.auth0Client.handleRedirectCallback();
      this.user = await this.auth0Client.getUser();
      await this.getUserData();
      this.isAuthenticated = true;
    } catch (e) {
      this.error = e;
    } finally {
      this.loading = false;
    }
  }
  /** Authenticates the user using the redirect method */
  loginWithRedirect(o = {
    returnTo: window.location.href
  }) {
    return this.auth0Client.loginWithRedirect(o);
  }
  /** Returns all the claims present in the ID token */
  getIdTokenClaims(o) {
    return this.auth0Client.getIdTokenClaims(o);
  }
  /** Returns the access token. If the token is invalid or missing, a new one is retrieved */
  getTokenSilently(o) {
    return this.auth0Client.getTokenSilently(o);
  }
  hasPermissions(permissions) {
    if (!Array.isArray(permissions)) {
      permissions = [permissions];
    }
    if (!this.identity.permissions) {
      return false;
    }
    while (permissions.length) {
      let next = permissions.pop();
      let found = this.identity.permissions.find(p => p == next);
      if (!found) {
        return false;
      }
    }
    return true;
  }
  hasRoles(roles) {
    if (!Array.isArray(roles)) {
      roles = [roles];
    }
    if (!this.userInfo.roles) {
      return false;
    }
    while (roles.length) {
      let next = roles.pop();
      let found = this.userInfo.roles.find(r => r == next);
      if (!found) {
        return false;
      }
    }
    return true;
  }

  async getIdentityClaims(token) {
    this.identity = JSON.parse(decodeToken(token));
    return this.identity;
  }

  /** Gets the access token using a popup window */
  getTokenWithPopup(o) {
    return this.auth0Client.getTokenWithPopup(o);
  }
  async getUserData() {
    try {
      this.auth0Client;
      let token = await this.getTokenSilently();
      let identity = await this.getIdentityClaims(token);
      this.bearer = "Bearer " + token;
      let res = await fetch(`https://${this.options.domain}/userinfo`, {
        headers: {
          authorization: this.bearer
        }
      });

      let userData = await res.json();
      for (var key in userData) {
        let keep = key;
        if (key.includes("https")) {
          keep = keep.slice(keep.lastIndexOf("/") + 1);
        }
        this.userInfo[keep] = userData[key]
      }
      this.user.isAuthenticated = true
      this.emit(this.AUTH_EVENTS.AUTHENTICATED, this)
    } catch (e) {
      console.error(e);
    }
  }
  /** Logs the user out and removes their session on the authorization server */
  logout(o = {
    returnTo: window.location.origin
  }) {
    let logout = this.auth0Client.logout(o);
    this.bearer = "";
    this.user = {};
    this.userInfo = {};
    this.identity = {};
    this.isAuthenticated = false;
    return logout;
  }

  /** Use this lifecycle method to instantiate the SDK client */
  async created(options) {
    this.emit(this.AUTH_EVENTS.LOADING)
    // Create a new instance of the SDK client using members of the given options object
    this.auth0Client = await createAuth0Client({
      domain: options.domain,
      client_id: options.clientId,
      audience: options.audience,
      redirect_uri: options.redirectUri
    });

    try {
      // If the user is returning to the app after authentication..
      if (
        window.location.search.includes("code=") &&
        window.location.search.includes("state=")
      ) {
        // handle the redirect and retrieve tokens
        const { appState } = await this.auth0Client.handleRedirectCallback();

        // Notify subscribers that the redirect callback has happened, passing the appState
        // (useful for retrieving any pre-authentication state)
        options.onRedirectCallback(appState);
      }
    } catch (e) {
      this.error = e;
    } finally {
      // Initialize our internal authentication state
      this.isAuthenticated = await this.auth0Client.isAuthenticated();
      this.user = await this.auth0Client.getUser();
      await this.getUserData();
      this.loading = false;
      this.emit(this.AUTH_EVENTS.LOADED)
    }
  }
}

/**
 * @param {{ onRedirectCallback: () => void; domain: string, audience: string, clientId: string  }} options
 */
export function initializeAuth(options) { return new AuthPlugin(options) }
export const $auth = () => { if (!instance) { throw new Error("Auth Plugin must be initialized prior to importing $auth") }; return instance }

export async function authGuard(to, from, next) {
  try {
    const authService = $auth();
    await onAuthLoaded();
    if (authService.isAuthenticated) {
      return next();
    }
    return instance.loginWithRedirect({ returnTo: to.fullPath });
  } catch (e) {
    return instance.loginWithRedirect({ returnTo: to.fullPath });
  }
}

/**
 * Promise resolves if able to authenticate
 * @param {function} [cb]
 */
export const onAuthLoaded = cb => {
  return new Promise((resolve, reject) => {
    const authService = $auth();
    if (!authService.loading) {
      if (typeof cb == 'function') { cb(authService) }
      return resolve(authService);
    }
    authService.on(authService.AUTH_EVENTS.LOADED, () => {
      resolve(authService)
      if (typeof cb == 'function') { cb(authService) }
    })
  });
};

function b64DecodeUnicode(str = ".") {
  try {
    return decodeURIComponent(
      atob(str).replace(/(.)/g, function (m, p) {
        var code = p
          .charCodeAt(0)
          .toString(16)
          .toUpperCase();
        if (code.length < 2) {
          code = "0" + code;
        }
        return "%" + code;
      })
    );
  } catch (e) {
    return "";
  }
}
function decodeToken(str = ".") {
  try {
    str = str.split(".")[1];
    var output = str.replace(/-/g, "+").replace(/_/g, "/");
    switch (output.length % 4) {
      case 0:
        break;
      case 2:
        output += "==";
        break;
      case 3:
        output += "=";
        break;
      default:
        throw "Illegal base64url string!";
    }

    return b64DecodeUnicode(output);
  } catch (err) {
    return atob(output);
  }
}