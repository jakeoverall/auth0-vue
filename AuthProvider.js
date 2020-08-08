/// SUMMARY this file is for type definitions only
/**
 * @typedef {{ domain?: string, audience?: string, client_id?: string, returnTo?: string, redirect_uri?: string, scope?: string, }} AuthOptions
 */
class AuthProvider {
  constructor() {
    this.loading = true;
    this.isAuthenticated = false;
    this.user = {};
    this.userInfo = {};
    this.identity = {};
    this.bearer = "";
    this.auth0Client = {};
    this.popupOpen = false;
    this.error = {};
  }

  /**
   * Retrieves and sets the users data with a refresh token if available
   */
  async getUserData() { }
  /**
   * Checks to see if the current user has all roles
   * @param {string | string[]} roles 
   * @returns {boolean}
   */
  hasRoles(roles) {
    return true;
  };
  /**
   * Checks to see if the current user has all permissions
   * @param {string | string[]} permissions 
   * @returns {boolean}
   */
  hasPermissions(permissions) {
    return true;
  };

  /** Authenticates the user using a popup window 
   * @param {AuthOptions} options
  */
  async loginWithPopup(options = {}) {

  }
  /** Authenticates the user using the redirect method 
   * @param {AuthOptions} options
  */
  loginWithRedirect(options = {}) {

  }
  /** Returns the access token. If the token is invalid or missing, a new one is retrieved 
   * @param {AuthOptions} options
  */
  getTokenSilently(options = {}) {
  }

  /** Gets the access token using a popup window 
   * @param {AuthOptions} options
  */
  getTokenWithPopup(options = {}) {
  }

  /** Logs the user out and removes their session on the authorization server 
   * @param {AuthOptions} options
  */
  logout(options = {}) {
  }

}
export const authProvider = new AuthProvider();