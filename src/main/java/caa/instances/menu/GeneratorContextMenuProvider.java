package caa.instances.menu;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import caa.component.ScopedDataboardDialog;
import caa.component.generator.Generator;
import caa.instances.Collector;
import caa.instances.Database;
import caa.utils.ConfigLoader;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public class GeneratorContextMenuProvider implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final Database db;
    private final ConfigLoader configLoader;
    private final Generator generator;
    private final Collector collector;

    public GeneratorContextMenuProvider(
        MontoyaApi api,
        Database db,
        ConfigLoader configLoader,
        Generator generator,
        Collector collector
    ) {
        this.api = api;
        this.db = db;
        this.configLoader = configLoader;
        this.generator = generator;
        this.collector = collector;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        Set<HttpRequestResponse> requestResponses = new LinkedHashSet<>();
        List<HttpRequest> requests = new ArrayList<>();

        requestResponses.addAll(event.selectedRequestResponses());

        Optional<MessageEditorHttpRequestResponse> editorRequestResponse =
                event.messageEditorRequestResponse();
        editorRequestResponse.ifPresent(messageEditorHttpRequestResponse ->
            requestResponses.add(messageEditorHttpRequestResponse.requestResponse())
        );

        for (HttpRequestResponse rr : requestResponses) {
            if (rr.request() == null) {
                continue;
            }
            requests.add(rr.request());
        }

        if (requestResponses.isEmpty()) {
            return List.of();
        }

        List<Component> menuItems = new ArrayList<>();

        JMenuItem rescanItem = new JMenuItem("Rescan");
        rescanItem.addActionListener(e -> {
            List<HttpRequestResponse> selectedMessages = new ArrayList<>(requestResponses);
            new SwingWorker<Integer, Void>() {
                @Override
                protected Integer doInBackground() {
                    int count = 0;
                    for (HttpRequestResponse message : selectedMessages) {
                        if (message.request() == null) {
                            continue;
                        }

                        if (collector.rescanFromContextMenu(message)) {
                            count++;
                        }
                    }
                    return count;
                }

                @Override
                protected void done() {
                    try {
                        int count = get();
                        JOptionPane.showMessageDialog(
                            null,
                            String.format(
                                "Rescan completed for %s message(s).",
                                count
                            ),
                            "CaA",
                            JOptionPane.INFORMATION_MESSAGE
                        );
                    } catch (Exception ex) {
                        api
                            .logging()
                            .logToError("Rescan: " + ex.getMessage());
                    }
                }
            }.execute();
        });

        menuItems.add(rescanItem);

        if (generator != null && !requests.isEmpty()) {
            JMenuItem sendToGeneratorItem = new JMenuItem("Send to CaA Generator");
            sendToGeneratorItem.addActionListener(e -> {
                for (HttpRequest request : requests) {
                    generator.insertNewTab(request, "Param", "");
                }
            });
            menuItems.add(sendToGeneratorItem);
        }

        JMenuItem viewInDataboardItem = new JMenuItem("View in Databoard");
        viewInDataboardItem.addActionListener(e ->
            ScopedDataboardDialog.show(
                api,
                db,
                configLoader,
                generator,
                collector,
                new ArrayList<>(requestResponses)
            )
        );

        menuItems.add(viewInDataboardItem);
        return menuItems;
    }
}
