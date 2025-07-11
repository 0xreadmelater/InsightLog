from insightlog.lib import filter_data

# Call with a file path that doesn't exist
result = filter_data(log_filter="ERROR", filepath="this_file_does_not_exist.log")

print("Returned:", result)