import fnmatch


class AlertAttributes:
    Alert_ID = "Alert.ID"
    Alert_Rule_Name = "Alert.Rule.Name"
    Alert_Rule_ID = "Alert.Rule.ID"
    Alert_TimeUTC = "Alert.TimeUTC"
    Alert_Rule_Severity_Name = "Alert.Rule.Severity.Name"
    Alert_Rule_Severity_ID = "Alert.Rule.Severity.ID"
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

    ExtraColumns = []

    def get_fields(self, extra_fields):
        output = self.Columns.copy()
        if extra_fields:
            for pattern in extra_fields:
                for m in fnmatch.filter(self.ExtraColumns, pattern):
                    if m not in output:
                        output.append(m)
        return output


class EventAttributes:
    Event_TimeUTC = "Event.TimeUTC"
    Event_ID = "Event.ID"
    Event_Type_Name = "Event.Type.Name"
    Event_Description = "Event.Description"
    Event_Operation_Name = "Event.Operation.Name"
    Event_ByAccount_SamAccountName = "Event.ByAccount.SamAccountName"
    Event_IP = "Event.IP"
    Event_Device_Name = "Event.Device.Name"
    Event_OnResource_Path = "Event.OnResource.Path"
    Event_OnObjectName = "Event.OnObjectName"
    Event_Alert_ID = "Event.Alert.ID"

    Columns = [
        Event_TimeUTC,
        Event_ID,
        Event_Type_Name,
        Event_Description,
        Event_Operation_Name,
        Event_ByAccount_SamAccountName,
        Event_IP,
        Event_Device_Name,
        Event_OnResource_Path,
        Event_OnObjectName,
        Event_Alert_ID,
    ]

    ExtraColumns = [
        "Event.*",  # allow wildcard requests if the API supports the field
    ]

    def get_fields(self, extra_fields):
        output = self.Columns.copy()
        if extra_fields:
            # If you pass explicit fields, include them directly.
            for field in extra_fields:
                if field not in output:
                    output.append(field)
        return output
