import createAuth0Client from "@auth0/auth0-spa-js";
import { authProvider } from "./AuthProvider";
/** Define a default action to perform after authentication */
const DEFAULT_REDIRECT_CALLBACK = () =>
  window.history.replaceState({}, document.title, window.location.pathname);

/**
 * @type {authProvider}
 */
let instance;

/** Returns the current instance of the SDK 
 * @returns {authProvider}
*/
export const getInstance = () => instance;
/** Returns the current instance of the SDK 
 * @returns {authProvider}
*/
export const $auth = () => instance;

/** Creates an instance of the Auth0 SDK. If one has already been created, it returns that instance */
export const useAuth0 = (
  {
    onRedirectCallback = DEFAULT_REDIRECT_CALLBACK,
    redirectUri = window.location.origin,
    ...options
  },
  Vue
) => {
  if (instance) return instance;

  // The 'instance' is simply a Vue object
  instance = new Vue({
    data() {
      return {
        loading: true,
        isAuthenticated: false,
        user: {},
        userInfo: {},
        identity: {},
        bearer: "",
        auth0Client: null,
        popupOpen: false,
        error: null
      };
    },
    methods: {
      /** Authenticates the user using a popup window */
      async loginWithPopup(o) {
        this.popupOpen = true;

        try {
          await this.auth0Client.loginWithPopup(o);
        } catch (e) {
          // eslint-disable-next-line
          console.error(e);
        } finally {
          this.popupOpen = false;
        }

        this.user = await this.auth0Client.getUser();
        await this.getUserData();
        this.isAuthenticated = true;
      },
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
      },
      /** Authenticates the user using the redirect method */
      loginWithRedirect(o) {
        return this.auth0Client.loginWithRedirect(o);
      },
      /** Returns all the claims present in the ID token */
      getIdTokenClaims(o) {
        return this.auth0Client.getIdTokenClaims(o);
      },
      /** Returns the access token. If the token is invalid or missing, a new one is retrieved */
      getTokenSilently(o) {
        return this.auth0Client.getTokenSilently(o);
      },
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
      },
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
      },

      async getIdentityClaims(token) {
        this.identity = JSON.parse(decodeToken(token));
        return this.identity;
      },

      /** Gets the access token using a popup window */
      getTokenWithPopup(o) {
        return this.auth0Client.getTokenWithPopup(o);
      },
      async getUserData() {
        try {
          this.auth0Client;
          let token = await this.getTokenSilently();
          let identity = await this.getIdentityClaims(token);
          this.bearer = "Bearer " + token;
          let res = await fetch(`https://${options.domain}/userinfo`, {
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
            this.$set(this.userInfo, keep, userData[key]);
          }
        } catch (e) {
          console.error(e);
        }
      },
      /** Logs the user out and removes their session on the authorization server */
      logout(o = {
        redirectTo: window.location.origin
      }) {
        let logout = this.auth0Client.logout(o);
        this.bearer = "";
        this.user = {};
        this.userInfo = {};
        this.identity = {};
        this.isAuthenticated = false;
        return logout;
      }
    },
    /** Use this lifecycle method to instantiate the SDK client */
    async created() {
      // Create a new instance of the SDK client using members of the given options object
      this.auth0Client = await createAuth0Client({
        domain: options.domain,
        client_id: options.clientId,
        audience: options.audience,
        redirect_uri: redirectUri
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
          onRedirectCallback(appState);
        }
      } catch (e) {
        this.error = e;
      } finally {
        // Initialize our internal authentication state
        this.isAuthenticated = await this.auth0Client.isAuthenticated();
        this.user = await this.auth0Client.getUser();
        await this.getUserData();
        this.loading = false;
      }
    }
  });

  return instance;
};
export async function authGuard(to, from, next) {
  try {
    const authService = getInstance();
    await onAuth();
    if (authService.isAuthenticated) {
      return next();
    }
  } catch (e) {
    return instance.loginWithRedirect({ appState: { targetUrl: to.fullPath } });
  }
}

/**
 * Promise resolves if able to authenticate
 * @param {function} [cb]
 */
export const onAuth = cb => {
  return new Promise((resolve, reject) => {
    const authService = getInstance();
    if (authService.isAuthenticated) {
      if (typeof cb == "function") {
        cb(authService);
      }
      return resolve();
    }
    authService.$watch("loading", loading => {
      if (authService.isAuthenticated === false) {
        return reject();
      }
      if (typeof cb == "function") {
        cb(authService);
      }
      return resolve();
    });
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

// Create a simple Vue plugin to expose the wrapper object throughout the application
export const Auth0Plugin = {
  install(Vue, options) {
    Vue.prototype.$auth = useAuth0(options, Vue);
  }
};
