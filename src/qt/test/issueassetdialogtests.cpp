// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying COPYING file.
#include <qt/issueassetdialog.h>
#include <QApplication>
#include <QDialogButtonBox>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QTextEdit>
#include <QTest>
#include <QTimer>
#include <stdexcept>

class IssueAssetDialogTests : public QObject {
    Q_OBJECT
    static bool status(IssueAssetDialog& dialog, const QString& text)
    {
        for (auto* label : dialog.findChildren<QLabel*>()) if (label->text().contains(text)) return true;
        return false;
    }
    static void dismissMessage()
    {
        QTimer::singleShot(0,[] {
            for (auto* widget : QApplication::topLevelWidgets())
                if (auto* message=qobject_cast<QMessageBox*>(widget)) message->accept();
        });
    }
private Q_SLOTS:
    void initTestCase()
    {
        // The native macOS style requires Cocoa, unavailable on headless plugins.
        QVERIFY(QApplication::setStyle("Fusion"));
    }
    void unavailable()
    {
        IssueAssetDialog dialog(nullptr);
        QVERIFY(status(dialog,"No client model"));
        bool disabled=false;
        for (auto* button : dialog.findChildren<QPushButton*>())
            if (button->text().contains("Issue")) disabled=!button->isEnabled();
        QVERIFY(disabled);
        QVERIFY(QMetaObject::invokeMethod(&dialog,"onIssueClicked",Qt::DirectConnection));
        QVERIFY(dialog.findChild<QTextEdit*>()->toPlainText().isEmpty());
    }
    void closeWithoutIssuing()
    {
        int calls=0;
        IssueAssetDialog dialog(nullptr,nullptr,[&](const UniValue&) {
            ++calls;
            return UniValue(UniValue::VOBJ);
        });
        const auto* buttons=dialog.findChild<QDialogButtonBox*>();
        QVERIFY(buttons);
        auto* close=buttons->button(QDialogButtonBox::Close);
        QVERIFY(close);
        dialog.show();
        QTest::mouseClick(close,Qt::LeftButton);
        QCOMPARE(dialog.result(),int(QDialog::Accepted));
        QVERIFY(!dialog.isVisible());
        QCOMPARE(calls,0);
    }
    void validationAndRpc()
    {
        int calls=0;
        int outcome=0;
        UniValue submitted;
        IssueAssetDialog dialog(nullptr,nullptr,[&](const UniValue& params) {
            ++calls;
            submitted=params;
            if (outcome==2) throw std::runtime_error("fake RPC failure");
            if (outcome==4) return UniValue(UniValue::VARR);
            UniValue result(UniValue::VOBJ);
            if (outcome==0) result.pushKV("asset","test-asset");
            if (outcome==3) result.pushKV("asset",42);
            return result;
        });
        QLineEdit* amount=nullptr;
        QLineEdit* tokens=nullptr;
        for (auto* edit : dialog.findChildren<QLineEdit*>()) {
            if (edit->placeholderText().startsWith("e.g. 1000")) amount=edit;
            if (edit->placeholderText().startsWith("e.g. 0")) tokens=edit;
        }
        QVERIFY(amount && tokens);
        for (const QString& invalid : {QString("0"),QString("-2"),QString("no")}) {
            amount->setText(invalid);
            dismissMessage();
            QVERIFY(QMetaObject::invokeMethod(&dialog,"onIssueClicked",Qt::DirectConnection));
            QCOMPARE(calls,0);
        }
        amount->setText("1.25");
        tokens->setText("0.5");
        for (outcome=0;outcome<5;++outcome) {
            if (outcome==2 || outcome==3) dismissMessage();
            QVERIFY(QMetaObject::invokeMethod(&dialog,"onIssueClicked",Qt::DirectConnection));
            QCOMPARE(calls,outcome+1);
            QVERIFY(submitted.isArray() && submitted.size()==2);
            QVERIFY(submitted[0].isStr() && submitted[1].isStr());
            QCOMPARE(QString::fromStdString(submitted[0].get_str()),QString("1.25"));
            QCOMPARE(QString::fromStdString(submitted[1].get_str()),QString("0.5"));
            if (outcome==0) QVERIFY(status(dialog,"Success! Asset ID: test-asset"));
            if (outcome==1 || outcome==4) QVERIFY(status(dialog,"Asset issued successfully"));
            if (outcome==2 || outcome==3) {
                QVERIFY(status(dialog,"Error issuing asset"));
                QVERIFY(dialog.findChild<QTextEdit*>()->toPlainText().contains("elements-cli issueasset 1.25 0.5"));
            }
        }
    }
    void amountConversionParity()
    {
        int calls=0;
        IssueAssetDialog dialog(nullptr,nullptr,[&](const UniValue&) {
            ++calls;
            return UniValue(UniValue::VOBJ);
        });
        QLineEdit* amount=nullptr;
        for (auto* edit : dialog.findChildren<QLineEdit*>())
            if (edit->placeholderText().startsWith("e.g. 1000")) amount=edit;
        QVERIFY(amount);
        for (const QString& input : {QString("0"),QString("-0"),QString("nan"),QString("inf"),
                QString("-inf"),QString("1e-300"),QString("-1e-300"),QString("1e999"),QString("")}) {
            amount->setText(input);
            const bool rejected=input.toDouble()<=0;
            const int before=calls;
            if (rejected) dismissMessage();
            QVERIFY(QMetaObject::invokeMethod(&dialog,"onIssueClicked",Qt::DirectConnection));
            QCOMPARE(calls,before+(rejected ? 0 : 1));
        }
    }
};
QTEST_MAIN(IssueAssetDialogTests)
#include "issueassetdialogtests.moc"
