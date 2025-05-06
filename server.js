require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const { Client } = require('@elastic/elasticsearch');
const dataSchema = require('./dataSchema');

// Configuration
const app = express();
const PORT = 3000;

const SECRET_KEY = process.env.SECRET_KEY;
const IV = process.env.IV;

const esClient = new Client({
  node: 'https://test-deployment-interns.es.us-east-1.aws.found.io/',
  auth: {
    username: 'mohdhamza_abbasi_tp@bmc.com',
    password: 'mohdhamza_abbasi_tp'
  }
});

// Middleware
app.post('/web', express.raw({ type: 'application/json', limit: '10mb' }), async (req, res) => {
  try {
    
    // 1. Verify Authorization
    const authResult = verifyAuthorization(req);
    if (!authResult.success) return res.status(400).send(authResult.message);

    // 2. Verify Data Integrity
    const checksumResult = verifyChecksum(req);
    if (!checksumResult.success) return res.status(400).send(checksumResult.message);

    // 3. Parse & Extract Relevant Data
    const parsedBody = JSON.parse(req.body.toString('utf8'));
    const filteredData = extractRequiredData(parsedBody);

    // 4. Validate Schema
    const validationResult = validateData(filteredData);
    if (!validationResult.valid) {
      console.error('Validation failed:', validationResult.errors);
      return res.status(400).json({ error: validationResult.errors });
    }

    // 5. Send to Elasticsearch
    try {
      await esClient.index({
        index: 'stepdata',
        document: filteredData,
      });
      console.log('✅ Data sent to Elasticsearch');
    } catch (error) {
      console.error('❌ Elasticsearch Error:', error);
    }

    res.status(200).send('Webhook Received!');
  } catch (err) {
    console.error("❌ Webhook Processing Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// --- Utility Functions ---

// Authorization Verification
function verifyAuthorization(req) {
  const encryptedTimestamp = req.header("X-Encrypted-Timestamp");
  if (!encryptedTimestamp) {
    console.error("Missing X-Encrypted-Timestamp header");
    return { success: false, message: "Missing timestamp header" };
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
    }

    console.error("❌ Authorization denied: Timestamp too old/new");
    return { success: false, message: "Authorization denied" };
  } catch (error) {
    console.error("❌ Decryption failed:", error.message);
    return { success: false, message: "Decryption failed" };
  }
}

// SHA256 Checksum
function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// Data Integrity Check
function verifyChecksum(req) {
  const receivedChecksum = req.header("X-Checksum");
  const rawBody = req.body.toString('utf8');
  const computedChecksum = sha256(rawBody);

  if (computedChecksum !== receivedChecksum) {
    console.error(`❌ Checksum mismatch\nComputed: ${computedChecksum}\nReceived: ${receivedChecksum}`);
    return { success: false, message: "Checksum mismatch. Possible data corruption." };
  }

  console.log("✅ Data integrity verified");
  return { success: true };
}

// Schema Validation
function validateData(data) {
  const { error } = dataSchema.validate(data, { abortEarly: false });
  return error
    ? { valid: false, errors: error.details.map(detail => detail.message) }
    : { valid: true };
}

// Data Extraction & Formatting
function extractRequiredData({ build_data, node_stage_data }) {
  const causeAction = build_data.actions.find(a => a._class === 'hudson.model.CauseAction');
  const queueAction = build_data.actions.find(a => a._class === 'jenkins.metrics.impl.TimeInQueueAction');

  const formattedStageData = node_stage_data.map(({ nodeId, data }) => ({
    id: data.id,
    name: data.name,
    execNode: data.execNode,
    status: data.status,
    ...(data.error !== undefined && { error: data.error }),
    startTimeMillis: data.startTimeMillis,
    durationMillis: data.durationMillis,
    pauseDurationMillis: data.pauseDurationMillis,
    stageFlowNodes: (data.stageFlowNodes || []).map(node => ({
      id: node.id,
      name: node.name,
      execNode: node.execNode,
      status: node.status,
      ...(node.error !== undefined && { error: node.error }),
      parameterDescription: node.parameterDescription,
      startTimeMillis: node.startTimeMillis,
      durationMillis: node.durationMillis,
      pauseDurationMillis: node.pauseDurationMillis,
      parentNodes: node.parentNodes
    }))
  }));

  return {
    causes: causeAction?.causes || [],
    timeInQueueMetrics: {
      blockedDurationMillis: queueAction?.blockedDurationMillis || 0,
      blockedTimeMillis: queueAction?.blockedTimeMillis || 0,
      buildableDurationMillis: queueAction?.buildableDurationMillis || 0,
      buildableTimeMillis: queueAction?.buildableTimeMillis || 0,
      buildingDurationMillis: queueAction?.buildingDurationMillis || 0,
      executingTimeMillis: queueAction?.executingTimeMillis || 0,
      executorUtilization: queueAction?.executorUtilization || 0,
      subTaskCount: queueAction?.subTaskCount || 0,
      waitingDurationMillis: queueAction?.waitingDurationMillis || 0,
      waitingTimeMillis: queueAction?.waitingTimeMillis || 0,
    },
    artifacts: build_data.artifacts || [],
    building: build_data.building,
    description: build_data.description,
    displayName: build_data.displayName,
    duration: build_data.duration,
    estimatedDuration: build_data.estimatedDuration,
    executor: build_data.executor || {},
    fullDisplayName: build_data.fullDisplayName,
    id: build_data.id,
    keepLog: build_data.keepLog,
    number: build_data.number,
    queueId: build_data.queueId,
    result: build_data.result,
    timestamp: build_data.timestamp,
    url: build_data.url,
    changeSets: build_data.changeSets || [],
    culprits: build_data.culprits || [],
    inProgress: build_data.inProgress,
    nextBuild: build_data.nextBuild,
    previousBuild: build_data.previousBuild,
    node_stage_data: formattedStageData
  };
}

// Start Server
app.listen(PORT, () => {
  console.log(`🚀 Webhook server running on http://localhost:${PORT}/web`);
});
