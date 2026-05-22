package caa.component;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import caa.component.datatable.Datatable;
import caa.component.datatable.DatatableContext;
import caa.component.datatable.Mode;
import caa.component.generator.Generator;
import caa.instances.Collector;
import caa.instances.Database;
import caa.utils.ConfigLoader;
import com.google.common.collect.LinkedHashMultimap;
import com.google.common.collect.SetMultimap;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ScopedDataboardDialog extends JDialog {

    private final JTabbedPane dataTabbedPane;

    private ScopedDataboardDialog() {
        super((Frame) null, "CaA Databoard", false);
        this.dataTabbedPane = new JTabbedPane(JTabbedPane.TOP);
        this.dataTabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);

        Rectangle screenBounds =
            GraphicsEnvironment.getLocalGraphicsEnvironment()
                .getDefaultScreenDevice()
                .getDefaultConfiguration()
                .getBounds();
        setSize(
            (int) (screenBounds.width * 0.6),
            (int) (screenBounds.height * 0.6)
        );
        setLocationRelativeTo(null);
        setLayout(new BorderLayout());
        add(dataTabbedPane, BorderLayout.CENTER);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
    }

    public static void show(
        MontoyaApi api,
        Database db,
        ConfigLoader configLoader,
        Generator generator,
        Collector collector,
        List<HttpRequestResponse> messages
    ) {
        new SwingWorker<Map<String, Object>, Void>() {
            @Override
            protected Map<String, Object> doInBackground() {
                return aggregateData(api, collector, messages);
            }

            @Override
            protected void done() {
                try {
                    Map<String, Object> scopedData = get();
                    if (scopedData.isEmpty()) {
                        JOptionPane.showMessageDialog(
                            null,
                            "No data could be extracted from the selected message(s).",
                            "CaA Databoard",
                            JOptionPane.INFORMATION_MESSAGE
                        );
                        return;
                    }

                    HttpRequest selectedRequest =
                        messages.size() == 1 ? messages.get(0).request() : null;
                    ScopedDataboardDialog dialog = new ScopedDataboardDialog();
                    dialog.populateData(
                        api,
                        db,
                        configLoader,
                        generator,
                        selectedRequest,
                        scopedData
                    );
                    dialog.setVisible(true);
                } catch (Exception e) {
                    api
                        .logging()
                        .logToError(
                            "ScopedDataboardDialog: " + e.getMessage()
                        );
                }
            }
        }
            .execute();
    }

    private void populateData(
        MontoyaApi api,
        Database db,
        ConfigLoader configLoader,
        Generator generator,
        HttpRequest request,
        Map<String, Object> scopedData
    ) {
        List<String> tabOrder = List.of(
            "Path",
            "FullPath",
            "File",
            "Param",
            "Value"
        );

        for (String tabName : tabOrder) {
            Object data = scopedData.get(tabName);
            if (data == null) {
                continue;
            }

            List<String> columns = new ArrayList<>();
            columns.add("Name");
            if ("Value".equals(tabName)) {
                columns.add("Value");
            }

            DatatableContext context = new DatatableContext(
                api,
                db,
                configLoader,
                generator,
                request
            );
            dataTabbedPane.addTab(
                tabName,
                new Datatable(context, columns, data, tabName, Mode.STANDARD)
            );
        }
    }

    private static Map<String, Object> aggregateData(
        MontoyaApi api,
        Collector collector,
        List<HttpRequestResponse> messages
    ) {
        Map<String, Set<String>> setData = new LinkedHashMap<>();
        setData.put("Path", new HashSet<>());
        setData.put("FullPath", new HashSet<>());
        setData.put("File", new HashSet<>());
        setData.put("Param", new HashSet<>());
        SetMultimap<String, String> valueData = LinkedHashMultimap.create();

        for (HttpRequestResponse message : messages) {
            try {
                Map<String, Object> collected = collector.collectForDataboard(
                    message
                );
                for (Map.Entry<String, Set<String>> entry : setData.entrySet()) {
                    Object data = collected.get(entry.getKey());
                    if (data instanceof Set<?>) {
                        entry.getValue().addAll((Set<String>) data);
                    }
                }
                Object values = collected.get("Value");
                if (values instanceof SetMultimap<?, ?>) {
                    valueData.putAll((SetMultimap<String, String>) values);
                }
            } catch (Exception e) {
                api
                    .logging()
                    .logToError(
                        "ScopedDataboardDialog: skipping malformed message: " +
                        e.getMessage()
                    );
            }
        }

        Map<String, Object> mergedData = new LinkedHashMap<>();
        for (Map.Entry<String, Set<String>> entry : setData.entrySet()) {
            if (!entry.getValue().isEmpty()) {
                mergedData.put(entry.getKey(), new HashSet<>(entry.getValue()));
            }
        }
        if (!valueData.isEmpty()) {
            mergedData.put("Value", valueData);
        }

        return mergedData;
    }
}