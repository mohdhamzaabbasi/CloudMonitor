const express = require('express');
const crypto = require('crypto');
const app = express();
require('dotenv').config();
app.use(express.json());
const util = require('util');
const { Client } = require('@elastic/elasticsearch');
const esClient = new Client({
    node: 'https://test-deployment-interns.es.us-east-1.aws.found.io/',
    auth: {
      username: 'mohdhamza_abbasi_tp@bmc.com',
      password: 'mohdhamza_abbasi_tp'
    }
  });

const SECRET_KEY = process.env.SECRET_KEY;
const IV = process.env.IV;
const PORT = process.env.PORT;
const dataSchema = require('./dataSchema');

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// Function to authorize
const verifyAuthorization = (req) => {
    const encryptedTimestamp = req.header("X-Encrypted-Timestamp");
    if (!encryptedTimestamp) {
        console.error("Missing X-Encrypted-Timestamp header");
        return false;
    }
    try {
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(SECRET_KEY), Buffer.from(IV));
        let decrypted = decipher.update(encryptedTimestamp, 'base64', 'utf8');
        decrypted += decipher.final('utf8');
        const receivedTimestamp = parseInt(decrypted, 10);
        const currentTimestamp = Date.now();
        if (Math.abs(currentTimestamp - receivedTimestamp) <= 600000) {
            console.log("✅ Authorization verified: Timestamp is within 10 minutes.");
            return { success: true };
        } else {
            console.error("Authorization denied.");
            return { success: false, message: "Authorization denied" };
        }
    } catch (error) {
        console.error("Decryption failed:", error.message);
        return false;
    }
}

// Function to verify Data Integrity
const verifyChecksum = (req) => {
    const { build_data, stage_data} = req.body;
    const checksum_build = req.header('X-Checksum-Build');
    const checksum_stage = req.header('X-Checksum-Stage');
    const computedChecksum_build = crypto.createHash('sha256').update(build_data).digest('hex');
    const computedChecksum_stage = crypto.createHash('sha256').update(stage_data).digest('hex');
    if (checksum_build === computedChecksum_build && checksum_stage === computedChecksum_stage) {
        console.log("✅ Data integrity verified!");
        return { success: true };
    } else {
        console.error("Checksum mismatch! Possible data tampering.");
        return { success: false, message: "Checksum mismatch. Possible data corruption." };
    }
}

// Function to extract only the required fields - BY SANVI
const extractRequiredData = (data, wfapi) => {
    return {
        "_class": "jenkins.metrics.impl.TimeInQueueAction",
        "blockedDurationMillis": data.actions?.find(action => action._class === "jenkins.metrics.impl.TimeInQueueAction")?.blockedDurationMillis || 0,
        "blockedTimeMillis": data.actions?.find(action => action._class === "jenkins.metrics.impl.TimeInQueueAction")?.blockedTimeMillis || 0,
        "buildableDurationMillis": data.actions?.find(action => action._class === "jenkins.metrics.impl.TimeInQueueAction")?.buildableDurationMillis || 0,
        "buildableTimeMillis": data.actions?.find(action => action._class === "jenkins.metrics.impl.TimeInQueueAction")?.buildableTimeMillis || 0,
        "buildingDurationMillis": data.actions?.find(action => action._class === "jenkins.metrics.impl.TimeInQueueAction")?.buildingDurationMillis || 0,
        "executingTimeMillis": data.actions?.find(action => action._class === "jenkins.metrics.impl.TimeInQueueAction")?.executingTimeMillis || 0,
        "executorUtilization": data.actions?.find(action => action._class === "jenkins.metrics.impl.TimeInQueueAction")?.executorUtilization || 0,
        "subTaskCount": data.actions?.find(action => action._class === "jenkins.metrics.impl.TimeInQueueAction")?.subTaskCount || 0,
        "waitingDurationMillis": data.actions?.find(action => action._class === "jenkins.metrics.impl.TimeInQueueAction")?.waitingDurationMillis || 0,
        "waitingTimeMillis": data.actions?.find(action => action._class === "jenkins.metrics.impl.TimeInQueueAction")?.waitingTimeMillis || 0,

        "_class_buildData": "hudson.plugins.git.util.BuildData",
        "buildsByBranchName": data.actions?.find(action => action._class === "hudson.plugins.git.util.BuildData")?.buildsByBranchName || {},
        "lastBuiltRevision": data.actions?.find(action => action._class === "hudson.plugins.git.util.BuildData")?.lastBuiltRevision || {},
        "remoteUrls": data.actions?.find(action => action._class === "hudson.plugins.git.util.BuildData")?.remoteUrls || [],
        "scmName": data.actions?.find(action => action._class === "hudson.plugins.git.util.BuildData")?.scmName || "",

        "artifacts": data.artifacts || [],
        "building": data.building,
        "description": data.description,
        "displayName": data.displayName,
        "duration": data.duration,
        "estimatedDuration": data.estimatedDuration,
        "executor": data.executor || {},
        "fullDisplayName": data.fullDisplayName,
        "id": data.id,
        "keepLog": data.keepLog,
        "number": data.number,
        "queueId": data.queueId,
        "result": data.result,
        "timestamp": data.timestamp,
        "url": data.url,

        "changeSets": data.changeSets || [],
        "culprits": data.culprits || [],

        "wfapi_describe": {
            "id": wfapi.id,
            "name": wfapi.name,
            "status": wfapi.status,
            "startTimeMillis": wfapi.startTimeMillis,
            "endTimeMillis": wfapi.endTimeMillis,
            "durationMillis": wfapi.durationMillis,
            "queueDurationMillis": wfapi.queueDurationMillis,
            "pauseDurationMillis": wfapi.pauseDurationMillis,
            "stages": wfapi.stages || []
        }
    };
};


// Function to validate the data
const validateData = (data) => {
    const { error, value } = dataSchema.validate(data, { allowUnknown: false, abortEarly: false });
    if (error) {
        return { valid: false, errors: error.details.map(err => err.message) };
    }
    return { valid: true, value };
};

app.post('/webhook', async (req, res) => {

    //Authorization
    const authResult = verifyAuthorization(req);
    if (!authResult.success) {
        return res.status(400).send(authResult.message);
    }

    //Check Data Integrity
    const checksumResult = verifyChecksum(req);
    if (!checksumResult.success) {
        return res.status(400).send(checksumResult.message);
    }

    //Normalization
    const filteredData = extractRequiredData(JSON.parse(req.body.build_data), JSON.parse(req.body.stage_data)); 
    console.log(util.inspect(filteredData, { showHidden: false, depth: null, colors: true }));
    const finalData=util.inspect(filteredData, { showHidden: false, depth: null, colors: true });
    //Validate the incoming data
    const validationResult = validateData(filteredData);
    if (!validationResult.valid) {
        return res.status(400).json({ error: validationResult.errors });
    }

    // Proceed with processing after validation
    console.log("✅ Data is valid");

    //Send data to Elasticsearch
    try {
        await esClient.index({
            index: 'metadata',
            document: filteredData,
        });
        console.log('✅ Data sent to Elasticsearch');
    } 
    catch (error) {
        console.error('❌ Error sending data to Elasticsearch:', error);
    }

    res.status(200).send('Webhook Received!');
});