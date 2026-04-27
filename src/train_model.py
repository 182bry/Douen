import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

from src.config.settings import (
    X_TRAIN,
    Y_TRAIN,
    X_VALID,
    Y_VALID,
    MODEL_PATH
)


def convert_to_binary(y_series):
    """
    Convert labels to binary:
    BENIGN -> 0
    ATTACK -> 1
    """
    return y_series.apply(lambda x: 0 if x == "BENIGN" else 1)


def main():
    print("Loading training and validation datasets...")

    X_train = pd.read_parquet(X_TRAIN)
    y_train = pd.read_parquet(Y_TRAIN)["Label"]

    X_valid = pd.read_parquet(X_VALID)
    y_valid = pd.read_parquet(Y_VALID)["Label"]

    print("Converting labels to binary classification...")
    y_train_binary = convert_to_binary(y_train)
    y_valid_binary = convert_to_binary(y_valid)

    print("Sampling training data for faster baseline training...")
    print("Creating balanced training sample...")

    train_df = X_train.copy()
    train_df["Label"] = y_train_binary

    benign = train_df[train_df["Label"] == 0]
    attack = train_df[train_df["Label"] == 1]

    attack_sample = attack.sample(n=50000, random_state=42)
    benign_sample = benign.sample(n=50000, random_state=42)

    balanced = pd.concat([benign_sample, attack_sample])

    X_train_sample = balanced.drop("Label", axis=1)
    y_train_sample = balanced["Label"]

    print("Balanced training shape:", X_train_sample.shape)


    print("Training Random Forest classifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"
    )

    model.fit(X_train_sample, y_train_sample)

    print("Saving trained model...")
    joblib.dump(model, MODEL_PATH)

    print("Making validation predictions...")
    y_pred = model.predict(X_valid)

    print("\nValidation Metrics")
    print("------------------")
    print("Accuracy :", accuracy_score(y_valid_binary, y_pred))
    print("Precision:", precision_score(y_valid_binary, y_pred))
    print("Recall   :", recall_score(y_valid_binary, y_pred))
    print("F1 Score :", f1_score(y_valid_binary, y_pred))

    print("\nConfusion Matrix")
    print("----------------")
    print(confusion_matrix(y_valid_binary, y_pred))

    print("\nClassification Report")
    print("---------------------")
    print(classification_report(y_valid_binary, y_pred, target_names=["BENIGN", "ATTACK"]))


if __name__ == "__main__":
    main()