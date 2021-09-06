package ro.gligor.dnsreport;

import com.itextpdf.text.DocumentException;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.io.FileNotFoundException;

import javafx.application.Application;

import static javafx.geometry.Pos.CENTER;


public class DNSReport extends Application{


    private final Button createReport;
    private final TextField domainField;
    private final Label titleLabel;

    public static void main(String[] args)  {
            launch(args);
        }

        public DNSReport(){
        createReport = new Button("Create report");
        domainField = new TextField();
        titleLabel = new Label("Report maker");
        }


    @Override
    public void start(Stage primaryStage){
        primaryStage.setTitle("DNS Report Maker");

        VBox layout = new VBox();
        layout.setAlignment(CENTER);
        layout.setPadding(new Insets(100,100,100,100));

        createReport.setOnAction(e->reportMaker(domainField.getText()));

        layout.getChildren().addAll(titleLabel, domainField, createReport);

        Scene scene = new Scene(layout, 500, 400);
        primaryStage.setScene(scene);
        primaryStage.show();
        primaryStage.setOnCloseRequest(e -> Platform.exit());
    }

    private void reportMaker(String domain) {
        PdfWriterClass writer = new PdfWriterClass();

        try {
            writer.createDocument(domain);
        } catch (FileNotFoundException | DocumentException e) {
            e.printStackTrace();
        }

        domainField.setText("");
    }
}



