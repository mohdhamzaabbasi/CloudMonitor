const Joi = require('joi');


const stageSchema = Joi.object({
    _links: Joi.object().unknown(true).required(), // Allowing any structure within _links
    id: Joi.string().required(),
    name: Joi.string().required(),
    execNode: Joi.string().allow(''), // Can be an empty string or a node identifier
    status: Joi.string().valid('IN_PROGRESS', 'SUCCESS', 'FAILED', 'ABORTED', 'UNSTABLE').required(),
    error: Joi.object().allow(''),
    startTimeMillis: Joi.number().integer().required(),
    durationMillis: Joi.number().integer().min(0).required(),
    pauseDurationMillis: Joi.number().integer().min(0).required()
});

const dataSchema = Joi.object({
    _class: Joi.string().valid('jenkins.metrics.impl.TimeInQueueAction').required(),
    blockedDurationMillis: Joi.number().integer().min(0).required(),
    blockedTimeMillis: Joi.number().integer().min(0).required(),
    buildableDurationMillis: Joi.number().integer().min(0).required(),
    buildableTimeMillis: Joi.number().integer().min(0).required(),
    buildingDurationMillis: Joi.number().integer().min(0).required(),
    executingTimeMillis: Joi.number().integer().min(0).required(),
    executorUtilization: Joi.number().min(0).max(1).required(),
    subTaskCount: Joi.number().integer().min(0).required(),
    waitingDurationMillis: Joi.number().integer().min(0).required(),
    waitingTimeMillis: Joi.number().integer().min(0).required(),
    _class_buildData: Joi.string().valid('hudson.plugins.git.util.BuildData').required(),
    buildsByBranchName: Joi.object().pattern(
        Joi.string(),
        Joi.object({
            _class: Joi.string().valid('hudson.plugins.git.util.Build').required(),
            buildNumber: Joi.number().integer().required(),
            buildResult: Joi.any().allow(null),
            marked: Joi.object().unknown(true).required(),
            revision: Joi.object().unknown(true).required()
        })
    ).required(),
    lastBuiltRevision: Joi.object({
        SHA1: Joi.string().length(40).required(),
        branch: Joi.array().items(Joi.object().unknown(true)).required()
    }).required(),
    remoteUrls: Joi.array().items(Joi.string().uri()).required(),
    scmName: Joi.string().allow(''),
    artifacts: Joi.array().items(Joi.object().unknown(true)),
    building: Joi.boolean().required(),
    description: Joi.any().allow(null),
    displayName: Joi.string().required(),
    duration: Joi.number().integer().min(0).required(),
    estimatedDuration: Joi.number().integer().min(0).required(),
    executor: Joi.object({
        _class: Joi.string().valid('hudson.model.OneOffExecutor').required()
    }).required(),
    fullDisplayName: Joi.string().required(),
    id: Joi.string().required(),
    keepLog: Joi.boolean().required(),
    number: Joi.number().integer().required(),
    queueId: Joi.number().integer().required(),
    result: Joi.string().valid('SUCCESS', 'FAILURE', 'ABORTED', 'UNSTABLE', null).allow(null),
    timestamp: Joi.number().integer().required(),
    url: Joi.string().uri().required(),
    changeSets: Joi.array().items(Joi.object().unknown(true)),
    culprits: Joi.array().items(Joi.object().unknown(true)),
    wfapi_describe: Joi.object({
        id: Joi.string().required(),
        name: Joi.string().required(),
        status: Joi.string().valid('IN_PROGRESS', 'SUCCESS', 'FAILURE', 'ABORTED', 'UNSTABLE').required(),
        startTimeMillis: Joi.number().integer().required(),
        endTimeMillis: Joi.number().integer().required(),
        durationMillis: Joi.number().integer().required(),
        queueDurationMillis: Joi.number().integer().required(),
        pauseDurationMillis: Joi.number().integer().required(),
        stages: Joi.array().items(stageSchema).required()
    }).required()
});

module.exports = dataSchema;