# @bcwdev/auth0-vue

This library is a small wrapper around auth0-spa-js. It is extended beyond the simple scale that is used in the auth0 tutorial. Added features include getting the `userInfo` and `identity` on login.

> REQUIRED: Enable RBAC in you application for the full set of features in this app. You can also add the following rule to retrieve more information in your userInfo

```javascript
// AUTH0 RULE
function (user, context, callback) {
  // please note auth0 will strip any non namespaced properties
  const namespace = 'https://YOURDOMAIN.auth0.com';
  const assignedRoles = (context.authorization || {}).roles;

  let idTokenClaims = context.idToken || {};

  idTokenClaims[`${namespace}/roles`] = assignedRoles;
  context.idToken = idTokenClaims;
  context.idToken[namespace + '/user_metadata'] = user.user_metadata;
  context.idToken[namespace + '/app_metadata'] = user.app_metadata;

  // namespaced properties are reduced to simple properties by this libary
  // so in vue you can access userInfo.app_metadata directly

  callback(null, user, context);
}
```

Fetching this extra data allows us to extend the basic methods for validating user roles and permissions.

On login `$auth.getUserData()` will be triggered

### Install

```javascript
import Vue from "vue";
import { Auth0Plugin } from "@bcwdev/auth0-vue";
// you will get these from your auth0 dashboard
import { domain, clientId, audience } from "./authconfig";

Vue.use(Auth0Plugin, {
  domain,
  clientId,
  audience,
  onRedirectCallback: appState => {
    router.push(
      appState && appState.targetUrl
        ? appState.targetUrl
        : window.location.pathname
    );
  }
});
```

### \$auth

You can access any of the following state properties directly from your vue components using `this.$auth`

```javascript
// $auth state
{
  loading: true,
  isAuthenticated: false,
  user: {},
  userInfo: {},
  identity: {},
  bearer: "",
}

// $auth methods
{
  /**
   * Sets userInfo, identity and bearer
   * @returns {Promise<void>}
  */
  getUserData()

  /**
   * Depends on UserData
   * @param {string[] | string} permissions
   * @returns {boolean}
  */
 hasPermissions(permissions) {},

  /**
   * Depends on UserData
   * @param {string[] | string} roles
   * @returns {boolean}
  */
  hasRoles(roles) {},
}

```

> Caution: `$auth.identity` is easily modifed on the client and therefore cannot be trusted when making server side decisions. Your server should use the bearer token and the auth0 api when handeling requests [see @bcwdev/auth0provider]('https://www.npmjs.com/package/@bcwdev/auth0provider')

Conditional rendering in vue templates based on roles or permissions can be accomplished directly from the `$auth` property

```html
<div v-if="$auth.hasRoles('admin')">
  <p>Only an admin can see me</p>
</div>
```
