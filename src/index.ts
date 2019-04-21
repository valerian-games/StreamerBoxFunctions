import * as functions from 'firebase-functions'
import * as admin from 'firebase-admin'

const serviceAccount = require('../serviceAccountKey.json');

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://valerian-games-dev.firebaseio.com"
});

const db = admin.firestore()
const auth = admin.auth()

import * as crypto from 'crypto'
import * as qs from 'querystring'
import axios from 'axios'

import CORS = require('cors');
const cors = CORS({ origin: true })

const redirect_uri = 'http://localhost:4200/c/redirect'

const firebaseConfig = functions.config()
const client_id = firebaseConfig.twitch.id;
const client_secret = firebaseConfig.twitch.secret;

const defaultParams = {
    client_id,
    redirect_uri
}

export const liveLastCommand
    = functions
        .firestore
        .document('live/{channelName}/{channelCollections}/{commandId}')
        .onWrite((change, context) => {
            const data = change.before.data()
            const channelName = context.params.channelName
            const command = context.params.channelCollections === "commands"
            const last = context.params.commandId === "last"

            if (data == undefined || !command || !last)
                return null

            const timestamp = data.timestamp

            return db
                .doc(`live/${channelName}`)
                .set({ lastCommand: timestamp }, { merge: true })
        })

export const oAuthRedirect = functions.https.onRequest((req, res) => {
    const base = 'https://id.twitch.tv/oauth2/authorize?';

    const queryParams = {
        ...defaultParams,
        response_type: 'code',
        state: crypto.randomBytes(20).toString('hex')
    }
    let endpoint = base + qs.stringify(queryParams)

    endpoint += '&scope=user:read:email+channel:read:subscriptions'

    res.redirect(endpoint);
})

export const token = functions.https.onRequest((req, res) => {
    cors(req, res, () => {

        return mintAuthToken(req)
            .then(authToken => res.json({ authToken }))
            .catch(err => console.log(err))

    });
});

async function mintAuthToken(req: functions.https.Request): Promise<string> {
    const base = 'https://id.twitch.tv/oauth2/token?'

    const queryParams = {
        ...defaultParams,
        client_secret,
        grant_type: 'authorization_code',
        code: req.query.code
    }

    const endpoint = base + qs.stringify(queryParams)

    const login = await axios.post(endpoint);
    const accessToken = login.data.access_token
    const refreshToken = login.data.refresh_token

    const user = await getTwitchUser(accessToken)
    const uid = user.display_name

    const authToken = await auth.createCustomToken(uid);

    const userData = {
        displayName: user.display_name,
        email: user.email,
        photoURL: user.profile_image_url,
        id: user.id,
        uid: uid,
        viewCount: user.view_count,
        type: user.type,
        description: user.description,
        offlinePhotoURL: user.offline_image_url
    }

    await db.doc(`channels/${uid}`).set(userData, { merge: true })
    await db.doc(`twitchTokens/${uid}`).set({ accessToken, refreshToken }, { merge: true })

    return authToken
}

async function getTwitchUser(accessToken: string): Promise<any> {
    const userUrl = 'https://api.twitch.tv/helix/users';

    const user = await axios.get(userUrl, { headers: { 'Authorization': `Bearer ${accessToken}` } });

    return user.data.data[0]
}