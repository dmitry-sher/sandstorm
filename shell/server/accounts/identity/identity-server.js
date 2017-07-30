// Sandstorm - Personal Cloud Sandbox
// Copyright (c) 2015 Sandstorm Development Group, Inc. and contributors
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { SandstormBackend } from "/imports/server/backend.js";

const linkIdentityToAccountInternal = function (db, backend, identityId, accountId, allowLogin) {
  // Links the identity to the account. If `allowLogin` is true, grants the identity login access
  // if possible. Makes the account durable if it is a demo account.

  check(db, SandstormDb);
  check(backend, SandstormBackend);
  check(identityId, String);
  check(accountId, String);

  const accountUser = Meteor.users.findOne({ _id: accountId });
  if (!accountUser) {
    throw new Meteor.Error(404, "No account found with ID " + accountId);
  }

  if (accountUser.profile) {
    throw new Meteor.Error(400, "Cannot link an identity to another identity.");
  }

  if (!!_.findWhere(accountUser.loginCredentials, { id: identityId }) ||
      !!_.findWhere(accountUser.nonloginCredentials, { id: identityId })) {
    throw new Meteor.Error("alreadyLinked",
      "Cannot link an identity that's alread linked to this account.");
  }

  const identityUser = Meteor.users.findOne({ _id: identityId });

  if (!identityUser) {
    throw new Meteor.Error(404, "No identity found with ID " + identityId);
  }

  if (!identityUser.profile) {
    throw new Meteor.Error(400, "Cannot link an account to another account");
  }

  db.deleteUnusedAccount(backend, identityUser._id);
  if (Meteor.users.findOne({ "loginCredentials.id": identityUser._id })) {
    throw new Meteor.Error(403,
                           "Cannot link an identity that can already log into another account");
  }

  const alreadyLinked = !!Meteor.users.findOne({ "nonloginCredentials.id": identityUser._id });

  const pushModifier = (alreadyLinked || !allowLogin)
        ? { nonloginCredentials: { id: identityUser._id } }
        : { loginCredentials: { id: identityUser._id } };

  let modifier;
  if (accountUser.expires) {
    if (alreadyLinked) {
      throw new Meteor.Error(403, "Cannot create an account for an identity that's " +
                                  "already linked to another account.");
    }

    modifier = {
      $push: pushModifier,
      $unset: { expires: 1 },
      $set: { upgradedFromDemo: Date.now() },
    };
    if (db.isReferralEnabled()) {
      // Demo users never got the referral notification. Send it now:
      db.sendReferralProgramNotification(accountUser._id);
    }

  } else {
    modifier = { $push: pushModifier };
  }

  // Make sure not to add the same identity twice.
  Meteor.users.update({ _id: accountUser._id,
                        "nonloginCredentials.id": { $ne: identityUser._id },
                        "loginCredentials.id": { $ne: identityUser._id }, },
                      modifier);

  if (accountUser.expires) {
    const demoIdentityId = SandstormDb.getUserIdentityIds(accountUser)[0];
    Meteor.users.update({ _id: demoIdentityId },
                        { $unset: { expires: 1 },
                          $set: { upgradedFromDemo: Date.now() }, });

    // Mark the demo identity as nonlogin. It'd be nicer if the identity started out as nonlogin,
    // but to get that to work we would need to adjust the account creation and first login logic.
    Meteor.users.update({ _id: accountUser._id,
                          "loginCredentials.id": demoIdentityId,
                          "nonloginCredentials.id": { $not: { $eq: demoIdentityId } }, },
                        { $pull: { loginCredentials: { id: demoIdentityId } },
                          $push: { nonloginCredentials: { id: demoIdentityId } }, });

  }
};

Meteor.methods({
  loginWithIdentity: function (accountUserId) {
    // Logs into the account with ID `accountUserId`. Throws an exception if the current user is
    // not an identity user listed in the account's `loginCredentials` field. This method is not
    // intended to be called directly; client-side code should only invoke it through
    // `Meteor.loginWithIdentity()`, which additionally maintains the standard Meteor client-side
    // login state.

    check(accountUserId, String);

    const identityUser = Meteor.user();
    if (!identityUser || !identityUser.profile) {
      throw new Meteor.Error(403, "Must be already logged in as an identity.");
    }

    const accountUser = Meteor.users.findOne(accountUserId);
    if (!accountUser) {
      throw new Meteor.Error(404, "No such user found: " + accountUserId);
    }

    const linkedIdentity = _.findWhere(accountUser.loginCredentials, { id: identityUser._id });

    if (!linkedIdentity) {
      throw new Meteor.Error(403, "Current identity is not a login identity for account "
                             + accountUserId);
    }

    return Accounts._loginMethod(this, "loginWithIdentity", [accountUserId],
                                 "identity", function () { return { userId: accountUserId }; });
  },

  createAccountForIdentity: function () {
    // Creates a new account for the currently-logged-in identity.

    const user = Meteor.user();
    if (!(user && user.profile)) {
      throw new Meteor.Error(403, "Must be logged in as an identity in order to create an account.");
    }

    if (Meteor.users.findOne({
      $or: [
        { "loginCredentials.id": user._id },
        { "nonloginCredentials.id": user._id },
      ],
    })) {
      throw new Meteor.Error(403, "Cannot create an account for an identity that's already " +
                                  "linked to another account.");
    }

    const newUser = {
      loginCredentials: [{ id: user._id }],
      nonloginCredentials: [],
    };
    if (user.services.dev) {
      newUser.signupKey = "devAccounts";
      if (user.services.dev.isAdmin) {
        newUser.isAdmin = true;
      }

      if (user.services.dev.hasCompletedSignup) {
        newUser.hasCompletedSignup = true;
      }
    } else if (user.expires) {
      // Demo user.
      newUser.expires = user.expires;
      if (!!user.appDemoId) {
        newUser.appDemoId = user.appDemoId;
      }
    }

    const options = {};

    // This will throw an error if the identity has been added as a login identity to some
    // other account while we were executing the body of this method.
    return Accounts.insertUserDoc(options, newUser);
  },

  linkIdentityToAccount: function (token) {
    // Links the identity of the current user to the account that has `token` as a resume token.
    // If the account is a demo account, makes the account durable and gives the identity login
    // access to it.

    check(token, String);

    if (!this.userId) {
      throw new Meteor.Error(403, "Cannot link to account if not logged in.");
    }

    const hashed = Accounts._hashLoginToken(token);
    const accountUser = Meteor.users.findOne({ "services.resume.loginTokens.hashedToken": hashed });

    linkIdentityToAccountInternal(this.connection.sandstormDb, this.connection.sandstormBackend,
                                  this.userId, accountUser._id, true);
  },

  unlinkIdentity: function (accountUserId, identityId) {
    // Unlinks the identity with ID `identityId` from the account with ID `accountUserId`.

    check(identityId, String);
    check(accountUserId, String);

    if (!this.userId) {
      throw new Meteor.Error(403, "Not logged in.");
    }

    if (!this.connection.sandstormDb.userHasIdentity(this.userId, identityId)) {
      throw new Meteor.Error(403, "Current user does not own identity " + identityId);
    }

    const identityUser = Meteor.users.findOne({ _id: identityId });
    Meteor.users.update({
      _id: accountUserId,
    }, {
      $pull: {
        nonloginCredentials: { id: identityId },
        loginCredentials: { id: identityId },
      },
    });
  },

  setIdentityAllowsLogin: function (identityId, allowLogin) {
    // Sets whether the current account allows the identity with ID `identityId` to log in.

    check(identityId, String);
    check(allowLogin, Boolean);
    if (!this.userId) {
      throw new Meteor.Error(403, "Not logged in.");
    }

    if (!this.connection.sandstormDb.userHasIdentity(this.userId, identityId)) {
      throw new Meteor.Error(403, "Current user does not own identity " + identityId);
    }

    if (allowLogin) {
      Meteor.users.update({ _id: this.userId,
                            "nonloginCredentials.id": identityId,
                            "loginCredentials.id": { $not: { $eq: identityId } }, },
                          { $pull: { nonloginCredentials: { id: identityId } },
                            $push: { loginCredentials: { id: identityId } }, });
    } else {
      Meteor.users.update({ _id: this.userId,
                            "loginCredentials.id": identityId,
                            "nonloginCredentials.id": { $not: { $eq: identityId } }, },
                          { $pull: { loginCredentials: { id: identityId } },
                            $push: { nonloginCredentials: { id: identityId } }, });
    }
  },

  logoutIdentitiesOfCurrentAccount: function () {
    // Logs out all identities that are allowed to log in to the current account.
    const user = Meteor.user();
    if (user && user.loginCredentials) {
      user.loginCredentials.forEach(function (identity) {
        Meteor.users.update({ _id: identity.id }, { $set: { "services.resume.loginTokens": [] } });
      });
    }
  },
});

Accounts.linkIdentityToAccount = function (db, backend, identityId, accountId, allowLogin) {
  // Links the identity to the account. If the account is a demo account, makes it durable.
  // If `allowLogin` is true, attempts to give the identity login access.
  check(db, SandstormDb);
  check(backend, SandstormBackend);
  check(identityId, String);
  check(accountId, String);
  check(allowLogin, Boolean);
  linkIdentityToAccountInternal(db, backend, identityId, accountId, allowLogin);
};

Meteor.publish("accountsOfIdentity", function (identityId) {
  check(identityId, String);
  if (!SandstormDb.ensureSubscriberHasIdentity(this, identityId)) return;

  // We maintain a map from identity IDs to live query handles that track profile changes.
  const loginCredentials = {};

  const _this = this;
  function addIdentitiesOfAccount(account) {
    account.loginCredentials.forEach(function (identity) {
      if (!(identity.id in loginCredentials)) {
        const user = Meteor.users.findOne({ _id: identity.id });
        if (user) {
          SandstormDb.fillInProfileDefaults(user);
          SandstormDb.fillInIntrinsicName(user);
          SandstormDb.fillInLoginId(user);
          const filteredUser = _.pick(user, "_id", "profile", "loginId");
          filteredUser.loginAccountId = account._id;
          filteredUser.sourceIdentityId = identityId;
          _this.added("loginCredentialsOfLinkedAccounts", user._id, filteredUser);
        }

        loginCredentials[identity.id] =
          Meteor.users.find({ _id: identity.id }, { fields: { profile: 1 } }).observeChanges({
            changed: function (id, fields) {
              _this.changed("loginCredentialsOfLinkedAccounts", id, fields);
            },
          });
      }
    });
  }

  const cursor = Meteor.users.find({
    $or: [
      { "loginCredentials.id": identityId },
      { "nonloginCredentials.id": identityId },
    ],
  });

  const handle = cursor.observe({
    added: function (account) {
      addIdentitiesOfAccount(account);
    },

    changed: function (newAccount, oldAccount) {
      addIdentitiesOfAccount(newAccount);
    },

    removed: function (account) {
      account.loginCredentials.forEach(function (identity) {
        if (identity.id in loginCredentials) {
          _this.removed("loginCredentialsOfLinkedAccounts", identity.id);
          loginCredentials[identity.id].stop();
          delete loginCredentials[identity.id];
        }
      });
    },
  });
  this.ready();

  this.onStop(function () {
    handle.stop();
    Object.keys(loginCredentials).forEach(function (identityId) {
      loginCredentials[identityId].stop();
      delete loginCredentials[identityId];
    });
  });
});
