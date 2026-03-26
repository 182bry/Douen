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

from config.settings import (
    X_TRAIN,
    Y_TRAIN,
    X_VALID,
    Y_VALID
)

MODEL_PATH = "models/random_forest_multiclass.pkl"


def main():
    print("Loading training and validation datasets...")

    X_train = pd.read_parquet(X_TRAIN)
    y_train = pd.read_parquet(Y_TRAIN)["Label"]

    X_valid = pd.read_parquet(X_VALID)
    y_valid = pd.read_parquet(Y_VALID)["Label"]

    print("Training label distribution:")
    print(y_train.value_counts())

    print("\nSampling training data for faster baseline training...")

    train_df = X_train.copy()
    train_df["Label"] = y_train

    sampled_parts = []

    for label, group in train_df.groupby("Label"):
        sample_size = min(len(group), 20000)
        sampled_parts.append(group.sample(n=sample_size, random_state=42))

    sampled_train = pd.concat(sampled_parts, ignore_index=True)

    X_train_sample = sampled_train.drop("Label", axis=1)
    y_train_sample = sampled_train["Label"]

    print("Sampled training shape:", X_train_sample.shape)
    print("\nSampled training label distribution:")
    print(y_train_sample.value_counts())

    print("\nTraining multiclass Random Forest classifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample"
    )

    model.fit(X_train_sample, y_train_sample)

    print("Saving trained multiclass model...")
    joblib.dump(model, MODEL_PATH)

    print("Making validation predictions...")
    y_pred = model.predict(X_valid)

    print("\nValidation Metrics")
    print("------------------")
    print("Accuracy :", accuracy_score(y_valid, y_pred))
    print("Precision:", precision_score(y_valid, y_pred, average="weighted", zero_division=0))
    print("Recall   :", recall_score(y_valid, y_pred, average="weighted", zero_division=0))
    print("F1 Score :", f1_score(y_valid, y_pred, average="weighted", zero_division=0))

    print("\nConfusion Matrix")
    print("----------------")
    print(confusion_matrix(y_valid, y_pred))

    print("\nClassification Report")
    print("---------------------")
    print(classification_report(y_valid, y_pred, zero_division=0))


if __name__ == "__main__":
    main()