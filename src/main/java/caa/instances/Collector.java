package caa.instances;

import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;
import static java.util.Collections.emptyList;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import caa.cache.CachePool;
import caa.utils.ConfigLoader;
import caa.utils.HashCalculator;
import caa.utils.HttpUtils;
import caa.utils.JsonTraverser;
import com.google.common.collect.LinkedHashMultimap;
import com.google.common.collect.SetMultimap;
import com.google.gson.JsonParser;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

public class Collector implements ScanCheck {

    private static class CollectResult {

        private final String host;
        private final Map<String, Object> data;

        private CollectResult(String host, Map<String, Object> data) {
            this.host = host;
            this.data = data;
        }
    }

    private final MontoyaApi api;
    private final Database db;
    private final ConfigLoader configLoader;
    private final HttpUtils httpUtils;

    public Collector(MontoyaApi api, Database db, ConfigLoader configLoader) {
        this.api = api;
        this.db = db;
        this.configLoader = configLoader;
        this.httpUtils = new HttpUtils(api, configLoader);
    }

    public static Map<String, Object> getJsonData(String responseBody) {
        String hashIndex = HashCalculator.calculateHash(
            responseBody.getBytes()
        );
        Map<String, Object> cachePool = CachePool.getFromCache(hashIndex);

        if (cachePool != null) {
            return cachePool;
        } else {
            // 遍历JSON Keys
            try {
                JsonTraverser jsonTraverser = new JsonTraverser();
                jsonTraverser.foreachJsonKey(
                    JsonParser.parseString(responseBody)
                );

                Map<String, Object> collectMap = getJsonObjectMap(
                    jsonTraverser
                );

                if (!collectMap.isEmpty()) {
                    CachePool.addToCache(hashIndex, collectMap);
                    return collectMap;
                } else {
                    return null;
                }
            } catch (Exception e) {
                return null;
            }
        }
    }

    private static Map<String, Object> getJsonObjectMap(
        JsonTraverser jsonTraverser
    ) {
        Map<String, Object> collectMap = new HashMap<>();
        Set<String> paramList = new LinkedHashSet<>(
            jsonTraverser.getJsonKeys()
        );
        SetMultimap<String, String> paramValueMap =
            jsonTraverser.getJsonKeyValues();

        if (paramValueMap != null && !paramValueMap.isEmpty()) {
            collectMap.put("jsonKeyValue", paramValueMap);
        }

        if (!paramList.isEmpty()) {
            collectMap.put("jsonKey", paramList);
        }

        return collectMap;
    }

    @Override
    public AuditResult activeAudit(
        HttpRequestResponse baseRequestResponse,
        AuditInsertionPoint auditInsertionPoint
    ) {
        return auditResult(emptyList());
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        collectAndStore(baseRequestResponse, "Proxy", true);
        return auditResult(emptyList());
    }

    public boolean rescanFromContextMenu(HttpRequestResponse baseRequestResponse) {
        return collectAndStore(baseRequestResponse, "Proxy", false);
    }

    private boolean collectAndStore(
        HttpRequestResponse baseRequestResponse,
        String toolType,
        boolean verifyToolScope
    ) {
        CollectResult collectResult = collectData(
            baseRequestResponse,
            toolType,
            true,
            true,
            true,
            true,
            verifyToolScope
        );

        if (collectResult.host.isBlank() || collectResult.data.isEmpty()) {
            return false;
        }

        CompletableFuture.supplyAsync(() -> {
            db.insertData(collectResult.host, collectResult.data);
            return null;
        }).exceptionally(ex -> {
            api
                .logging()
                .logToError(
                    "Failed to insert data asynchronously: " +
                    ex.getMessage()
                );
            return null;
        });

        return true;
    }

    private void processJsonData(
        Map<String, Object> jsonData,
        SetMultimap<String, String> valueList,
        Set<String> paramList
    ) {
        Object jsonKeyValue = jsonData.get("jsonKeyValue");
        Object jsonKey = jsonData.get("jsonKey");
        if (jsonKeyValue != null) {
            valueList.putAll((SetMultimap) jsonKeyValue);
        }
        if (jsonKey != null) {
            paramList.addAll((HashSet) jsonKey);
        }
    }

    private void processPath(
        String path,
        Set<String> pathList,
        Set<String> fileList,
        Set<String> fullPathList
    ) {
        if ("/".equals(path)) {
            return;
        }
        Arrays.stream(path.split("/"))
            .filter(p -> !p.isBlank())
            .forEach(p -> {
                if (
                    p.contains(".") &&
                    !p.equals(".") &&
                    p.indexOf(".") != p.length() - 1
                ) {
                    if (fileList != null) {
                        fileList.add(p);
                    }
                } else {
                    pathList.add(p.replaceAll(":", ""));
                }
            });
        if (fullPathList != null) {
            fullPathList.add(path);
        }
    }

    private void processParameters(
        List<ParsedHttpParameter> paramsList,
        Set<String> paramList,
        SetMultimap<String, String> valueList
    ) {
        for (ParsedHttpParameter param : paramsList) {
            String paramName = httpUtils
                .decodeParameter(param.name())
                .trim()
                .replaceAll("\\?", "");
            if ("_".equals(paramName)) {
                paramName = paramName.replace("_", "");
            }
            if (!paramName.isBlank() && paramName.matches("[\\w\\-\\.]+")) {
                paramList.add(paramName);
                String paramValue = httpUtils.decodeParameter(param.value());
                if (!paramValue.isBlank()) {
                    Map<String, Object> jsonData = getJsonData(paramValue);
                    if (jsonData != null) {
                        processJsonData(jsonData, valueList, paramList);
                    } else {
                        valueList.put(paramName, paramValue);
                    }
                }
            }
        }
    }

    private boolean processResponseBodyJson(
        ByteArray responseBodyBytes,
        Set<String> paramList,
        SetMultimap<String, String> valueList
    ) {
        String hashIndex = HashCalculator.calculateHash(
            responseBodyBytes.getBytes()
        );
        Map<String, Object> cachePool = CachePool.getFromCache(hashIndex);

        if (cachePool != null) {
            processJsonData(cachePool, valueList, paramList);
            return true;
        }

        try {
            String responseBody = new String(
                responseBodyBytes.getBytes(),
                StandardCharsets.UTF_8
            );
            Map<String, Object> jsonData = getJsonData(responseBody);
            if (jsonData != null) {
                processJsonData(jsonData, valueList, paramList);
                CachePool.addToCache(hashIndex, jsonData);
                return true;
            }
        } catch (Exception e) {
            api
                .logging()
                .logToError(
                    "Failed to parse response body JSON: " + e.getMessage()
                );
        }

        return false;
    }

    private void processResponseBody(
        ByteArray responseBodyBytes,
        Set<String> paramList,
        SetMultimap<String, String> valueList
    ) {
        if (!processResponseBodyJson(responseBodyBytes, paramList, valueList)) {
            try {
                String responseBody = new String(
                    responseBodyBytes.getBytes(),
                    StandardCharsets.UTF_8
                );
                processHtmlInputs(responseBody, paramList, valueList);
            } catch (Exception e) {
                api
                    .logging()
                    .logToError(
                        "Failed to parse response body HTML: " + e.getMessage()
                    );
            }
        }
    }

    private void processHtmlInputs(
        String html,
        Set<String> paramList,
        SetMultimap<String, String> valueList
    ) {
        try {
            Document doc = Jsoup.parse(html);
            Elements inputTags = doc.getElementsByTag("input");

            for (Element inputTag : inputTags) {
                String type = inputTag.attr("type");
                if ("hidden".equals(type) || "text".equals(type)) {
                    String name = inputTag.attr("name");
                    if (name.isBlank()) {
                        name = inputTag.attr("id");
                    }
                    if (!name.isBlank() && name.matches("[\\w\\-\\.]+")) {
                        paramList.add(name);
                        String value = inputTag.attr("value");
                        if (!value.isBlank()) {
                            valueList.put(name, value);
                        }
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Failed to parse HTML: " + e.getMessage());
        }
    }

    private void processResponseOnly(
        HttpResponse response,
        SetMultimap<String, String> valueList,
        Set<String> paramList
    ) {
        if (response != null) {
            processResponseBodyJson(response.body(), paramList, valueList);
        }
    }

    public Map<String, Object> collect(
        HttpRequestResponse baseRequestResponse
    ) {
        return collectData(
            baseRequestResponse,
            "Proxy",
            true,
            false,
            false,
            false,
            true
        ).data;
    }

    public Map<String, Object> collectForDataboard(
        HttpRequestResponse baseRequestResponse
    ) {
        return collectData(
            baseRequestResponse,
            "Proxy",
            false,
            true,
            true,
            false,
            false
        ).data;
    }

    private CollectResult collectData(
        HttpRequestResponse baseRequestResponse,
        String toolType,
        boolean applyScopeFilter,
        boolean includeExtendedPathData,
        boolean includeHtmlInputs,
        boolean includeAllTables,
        boolean verifyToolScope
    ) {
        Map<String, Object> resultMap = new HashMap<>();
        Set<String> pathList = new HashSet<>();
        Set<String> fullPathList = new HashSet<>();
        Set<String> fileList = new HashSet<>();
        Set<String> paramList = new HashSet<>();
        SetMultimap<String, String> valueList = LinkedHashMultimap.create();

        HttpRequest request = baseRequestResponse.request();
        HttpResponse response = baseRequestResponse.response();
        String host = "";

        if (request != null) {
            String path = "";
            try {
                URL u = new URL(request.url());
                path = u.getPath().replaceAll("/+", "/");
                host = u.getHost().toLowerCase();
            } catch (Exception e) {
                api
                    .logging()
                    .logToError("Failed to parse URL: " + e.getMessage());
            }

            boolean matches = applyScopeFilter &&
            httpUtils.verifyHttpRequestResponse(
                baseRequestResponse,
                toolType,
                verifyToolScope
            );
            if (!matches) {
                processPath(
                    path,
                    pathList,
                    includeExtendedPathData ? fileList : null,
                    includeExtendedPathData ? fullPathList : null
                );
                processParameters(request.parameters(), paramList, valueList);

                if (response != null) {
                    if (includeHtmlInputs) {
                        processResponseBody(response.body(), paramList, valueList);
                    } else {
                        processResponseBodyJson(
                            response.body(),
                            paramList,
                            valueList
                        );
                    }
                }
            }
        }

        if (request == null && response != null) {
            processResponseOnly(response, valueList, paramList);
        }

        addCollectedData(resultMap, pathList, "Path", includeAllTables);
        if (includeExtendedPathData) {
            addCollectedData(resultMap, fullPathList, "FullPath", includeAllTables);
            addCollectedData(resultMap, fileList, "File", includeAllTables);
        }
        addCollectedData(resultMap, paramList, "Param", includeAllTables);
        if (!valueList.isEmpty()) {
            resultMap.put("Value", valueList);
        }

        return new CollectResult(host, resultMap);
    }

    private void addCollectedData(
        Map<String, Object> resultMap,
        Set<String> dataList,
        String tableName,
        boolean includeAllTables
    ) {
        if (dataList.isEmpty()) {
            return;
        }
        resultMap.put(tableName, dataList);
        if (includeAllTables) {
            resultMap.put("All " + tableName, dataList);
        }
    }

    @Override
    public ConsolidationAction consolidateIssues(
        AuditIssue newIssue,
        AuditIssue existingIssue
    ) {
        return existingIssue.name().equals(newIssue.name())
            ? KEEP_EXISTING
            : KEEP_BOTH;
    }
}
