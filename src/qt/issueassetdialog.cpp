// Copyright (c) 2026 The LayerTwo Labs developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/issueassetdialog.h>
#include <haskell/bridge.h>

#include <qt/clientmodel.h>
#include <qt/guiutil.h>

#include <interfaces/node.h>
#include <univalue.h>

#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QTextEdit>
#include <QVBoxLayout>

#include <string>
#include <stdexcept>
#include <utility>

IssueAssetDialog::IssueAssetDialog(ClientModel* clientModel, QWidget* parent)
    : IssueAssetDialog(clientModel, parent, clientModel ? IssueRpc{[clientModel](const UniValue& params) {
        return clientModel->node().executeRpc("issueasset", params, "");
      }} : IssueRpc{})
{
}

IssueAssetDialog::IssueAssetDialog(ClientModel*, QWidget* parent, IssueRpc rpc)
    : QDialog(parent), m_rpc(std::move(rpc))
{
    setWindowTitle(tr("Issue New Asset (Elements)"));
    setModal(true);
    setMinimumWidth(500);

    auto* layout = new QVBoxLayout(this);

    m_status_label = new QLabel(tr("Issue a new asset on Elements. This uses the 'issueasset' RPC. Amounts are in BTC units (8 decimals)."), this);
    m_status_label->setWordWrap(true);
    layout->addWidget(m_status_label);

    auto* form = new QFormLayout();

    m_asset_amount_edit = new QLineEdit("10", this);
    m_asset_amount_edit->setPlaceholderText("e.g. 1000.0");
    form->addRow(tr("Asset amount (L-BTC units):"), m_asset_amount_edit);

    m_token_amount_edit = new QLineEdit("1", this);
    m_token_amount_edit->setPlaceholderText("e.g. 0 or 1");
    form->addRow(tr("Reissuance token amount:"), m_token_amount_edit);

    m_asset_name_edit = new QLineEdit("", this);
    m_asset_name_edit->setPlaceholderText("(optional) name for your reference");
    form->addRow(tr("Asset name (UI only):"), m_asset_name_edit);

    layout->addLayout(form);

    m_result_text = new QTextEdit(this);
    m_result_text->setReadOnly(true);
    m_result_text->setPlaceholderText(tr("Result will appear here (asset ID, txid, etc.)"));
    layout->addWidget(m_result_text);

    auto* buttonBox = new QDialogButtonBox(this);
    m_issue_button = buttonBox->addButton(tr("&Issue Asset"), QDialogButtonBox::AcceptRole);
    m_close_button = buttonBox->addButton(QDialogButtonBox::Close);
    layout->addWidget(buttonBox);

    connect(m_issue_button, &QPushButton::clicked, this, &IssueAssetDialog::onIssueClicked);
    connect(m_close_button, &QPushButton::clicked, this, &QDialog::accept);

    if (!m_rpc) {
        m_status_label->setText(tr("No client model available. Cannot issue assets."));
        m_issue_button->setEnabled(false);
    }
}

void IssueAssetDialog::onIssueClicked()
{
    UniValue result;
    const auto action = [&](uint32_t step) -> uint32_t {
        switch (step) {
        case 1: return static_cast<bool>(m_rpc);
        case 2: m_result_text->clear(); m_status_label->setText(tr("Issuing...")); return 1;
        case 3: return drivechain::haskell::RejectWalletIssueAmount(m_asset_amount_edit->text().toDouble());
        case 4: QMessageBox::warning(this,tr("Error"),tr("Asset amount must be positive.")); return 1;
        case 5: {
            UniValue params(UniValue::VARR);
            params.push_back(m_asset_amount_edit->text().toStdString());
            params.push_back(m_token_amount_edit->text().toStdString());
            result=m_rpc(params);
            m_result_text->setPlainText(QString::fromStdString(result.write(2)));
            return result.isObject();
        }
        case 6: return result.exists("asset");
        case 7:
            m_status_label->setText(tr("Success! Asset ID: %1 (copy from result)").arg(QString::fromStdString(result["asset"].get_str()))); return 1;
        case 8: m_status_label->setText(tr("Asset issued successfully. See result below.")); return 1;
        default: throw std::logic_error("invalid asset issuance action");
        }
    };
    using namespace drivechain::haskell;
    if (!ParentReplayStore(ReplayStoreFlow::WALLET_ISSUE_PREFLIGHT,action)) return;
    try {
        ParentReplayStore(ReplayStoreFlow::WALLET_ISSUE_RESULT,action);
    } catch (const std::exception& e) {
        m_status_label->setText(tr("Error issuing asset."));
        m_result_text->setPlainText(QString("Error: %1\n\nTry using elements-cli issueasset %2 %3 or the RPC console.")
            .arg(QString::fromStdString(e.what()))
            .arg(m_asset_amount_edit->text())
            .arg(m_token_amount_edit->text()));
        QMessageBox::critical(this, tr("Issue Asset Error"), QString::fromStdString(e.what()));
    }
}
