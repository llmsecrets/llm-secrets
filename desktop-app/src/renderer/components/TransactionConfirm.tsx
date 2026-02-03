import * as React from 'react';
import { useState, useEffect } from 'react';
import './TransactionConfirm.css';

interface TransactionDetails {
  id: string;
  to: string;
  toDisplay: string;
  value: string;
  valueDisplay: string;
  gasDisplay: string;
  totalCost: string;
  network: string;
  networkName: string;
  functionName?: string;
  functionArgs?: string[];
  data?: string;
}

interface TransactionConfirmProps {
  transaction: TransactionDetails | null;
  onConfirm: () => void;
  onCancel: () => void;
}

export const TransactionConfirm: React.FC<TransactionConfirmProps> = ({
  transaction,
  onConfirm,
  onCancel,
}) => {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  if (!transaction) {
    return null;
  }

  const handleConfirm = async () => {
    setIsSubmitting(true);
    try {
      await onConfirm();
    } finally {
      setIsSubmitting(false);
    }
  };

  const isContractCall = !!transaction.functionName;

  return (
    <div className="tx-confirm-overlay">
      <div className="tx-confirm-modal">
        <div className="tx-confirm-header">
          <h2>Confirm Transaction</h2>
          <span className={`network-badge network-${transaction.network}`}>
            {transaction.networkName}
          </span>
        </div>

        <div className="tx-confirm-body">
          {isContractCall ? (
            <>
              <div className="tx-section">
                <label>Contract</label>
                <div className="tx-value address">{transaction.toDisplay}</div>
              </div>

              <div className="tx-section">
                <label>Function</label>
                <div className="tx-value function">
                  <code>{transaction.functionName}</code>
                </div>
              </div>

              {transaction.functionArgs && transaction.functionArgs.length > 0 && (
                <div className="tx-section">
                  <label>Arguments</label>
                  <div className="tx-args">
                    {transaction.functionArgs.map((arg, i) => (
                      <div key={i} className="tx-arg">
                        <span className="arg-index">{i}</span>
                        <code className="arg-value">{arg}</code>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {transaction.valueDisplay !== '0' && (
                <div className="tx-section">
                  <label>Value</label>
                  <div className="tx-value amount">{transaction.valueDisplay}</div>
                </div>
              )}
            </>
          ) : (
            <>
              <div className="tx-section">
                <label>To</label>
                <div className="tx-value address">{transaction.toDisplay}</div>
              </div>

              <div className="tx-section">
                <label>Amount</label>
                <div className="tx-value amount">{transaction.valueDisplay}</div>
              </div>
            </>
          )}

          <div className="tx-section">
            <label>Estimated Gas</label>
            <div className="tx-value gas">{transaction.gasDisplay}</div>
          </div>

          <div className="tx-section total">
            <label>Total Cost</label>
            <div className="tx-value total-cost">{transaction.totalCost}</div>
          </div>

          {showAdvanced && transaction.data && (
            <div className="tx-section advanced">
              <label>Data</label>
              <div className="tx-data">
                <code>{transaction.data}</code>
              </div>
            </div>
          )}

          {transaction.data && transaction.data !== '0x' && (
            <button
              className="btn-link"
              onClick={() => setShowAdvanced(!showAdvanced)}
            >
              {showAdvanced ? 'Hide' : 'Show'} transaction data
            </button>
          )}
        </div>

        <div className="tx-confirm-warning">
          <svg viewBox="0 0 24 24" width="20" height="20">
            <path
              fill="currentColor"
              d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 15v-2h2v2h-2zm0-4V7h2v6h-2z"
            />
          </svg>
          <span>
            This transaction will be signed with your private key and broadcast
            to the {transaction.networkName} network. This action cannot be undone.
          </span>
        </div>

        <div className="tx-confirm-actions">
          <button
            className="btn-secondary"
            onClick={onCancel}
            disabled={isSubmitting}
          >
            Cancel
          </button>
          <button
            className="btn-primary btn-confirm"
            onClick={handleConfirm}
            disabled={isSubmitting}
          >
            {isSubmitting ? (
              <>
                <span className="spinner" />
                Signing...
              </>
            ) : (
              'Sign & Send'
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

export default TransactionConfirm;
