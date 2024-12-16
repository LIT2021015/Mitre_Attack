# from flask import Flask, request, render_template, jsonify
# import requests

# app = Flask(__name__)


# @app.route("/")
# def index():
#     return render_template("index.html")


# @app.route("/get_cve_info", methods=["POST"])
# def get_cve_info():
#     cve_id = request.form["cve_id"]
#     url = f"https://cve.circl.lu/api/cve/CVE-1999-1015"
#     # https://cve.circl.lu/api/cve/CVE-1999-1015

#     try:
#         response = requests.get(url)
#         response.raise_for_status()
#         data = response.json()

#         if data:
#             # Extract relevant data
#             description = (
#                 data.get("cve", {})
#                 .get("description", {})
#                 .get("description_data", [{}])[0]
#                 .get("value", "No description available")
#             )
#             published_date = data.get("cve", {}).get(
#                 "publishedDate", "No published date"
#             )
#             cvss_score = (
#                 data.get("impact", {})
#                 .get("baseMetricV2", {})
#                 .get("score", "No CVSS score")
#             )

#             result = {
#                 "CVE ID": cve_id,
#                 "Description": description,
#                 "Published Date": published_date,
#                 "CVSS Score": cvss_score,
#             }

#             return jsonify(data)
#         else:
#             return jsonify({"error": "No data found for this CVE ID."})

#     except requests.exceptions.RequestException as e:
#         return jsonify({"error": str(e)})


# if __name__ == "__main__":
#     app.run(debug=True)

from flask import Flask, render_template, request, jsonify
import requests
import pandas as pd

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    cve_info = {}
    cve_df = pd.DataFrame()  # Initialize an empty DataFrame for the table

    if request.method == "POST":
        # Get the CVE ID from the form input
        cve_id = request.form["cve_id"]

        # URL for the CVE API using the entered CVE ID
        url = f"https://cve.circl.lu/api/cve/{cve_id}"

        try:
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()

            if data:
                # Extract relevant data
                cve_info = {
                    "Published": data.get("cve", {}).get(
                        "publishedDate", "No Published Date"
                    ),
                    "Access": data.get("access", {}),
                    "ID": data.get("id", ""),
                    "Impact": data.get("impact", {}),
                    "Bugtraq": ", ".join(data.get("refmap", {}).get("bugtraq", [])),
                    "Summary": data.get("summary", "No summary available"),
                }

                # Load the updated CVE data from the CSV file
                df = pd.read_csv("updated_cve_data.csv")

                # Combine the CVE data with the CSV data
                df["Access"] = cve_info["Access"]
                df["Impact"] = cve_info["Impact"]
                df["Bugtraq"] = cve_info["Bugtraq"]
                df["Summary"] = cve_info["Summary"]

                # Extract relevant columns for display
                cve_df = df[
                    [
                        "Environments",
                        "Attack Vectors",
                        "Prerequisites",
                        "Potential Outputs",
                        "TTPs",
                        "Access",
                        "Impact",
                        "Bugtraq",
                        "Summary",
                    ]
                ]

            else:
                cve_info = {"error": "No data found for this CVE ID."}

        except requests.exceptions.RequestException as e:
            cve_info = {"error": str(e)}

    return render_template(
        "index.html", cve_info=cve_info, cve_df=cve_df.to_dict(orient="records")
    )


if __name__ == "__main__":
    app.run(debug=True)
