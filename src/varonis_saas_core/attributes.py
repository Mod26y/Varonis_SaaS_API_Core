import fnmatch

class AlertAttributes:
    Alert_ID = "Alert.ID"
    Alert_Rule_Name = "Alert.Rule.Name"
    Alert_Rule_ID = "Alert.Rule.ID"
    Alert_TimeUTC = "Alert.TimeUTC"
    Alert_Rule_Severity_Name = "Alert.Rule.Severity.Name"
    Alert_Rule_Severity_ID = "Alert.Rule.Severity.ID"
    Alert_Rule_Category_ID = "Alert.Rule.Category.ID"
    Alert_Status_ID = "Alert.Status.ID"
    Alert_Device_HostName = "Alert.Device.HostName"
    Alert_User_Identity_Name = "Alert.User.Identity.Name"
    Alert_AggregationFilter = "Alert.AggregationFilter"
    Alert_IngestTime = "Alert.IngestTime"

    Columns = [
        Alert_Rule_Name,
        Alert_Rule_Severity_Name,
        Alert_TimeUTC,
        Alert_ID,
        Alert_Rule_ID,
        Alert_Rule_Severity_ID,
        Alert_Status_ID,
        Alert_Device_HostName,
        Alert_User_Identity_Name,
        Alert_IngestTime,
    ]

    ExtraColumns = [
        Alert_Rule_Category_ID,
    ]

    def get_fields(self, extra_fields):
        output = self.Columns.copy()
        if extra_fields:
            for pattern in extra_fields:
                matches = fnmatch.filter(self.ExtraColumns, pattern)
                for m in matches:
                    if m not in output:
                        output.append(m)
        return output

class EventAttributes:
    Event_TimeUTC = "Event.TimeUTC"
    Event_Alert_ID = "Event.Alert.ID"

    Columns = [
        Event_TimeUTC,
        Event_Alert_ID,
    ]

    ExtraColumns = []

    def get_fields(self, extra_fields):
        output = self.Columns.copy()
        # currently no extras, but keep API consistent
        return output
