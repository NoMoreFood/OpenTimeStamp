function LoadIisWebsites()
{
    var previous = Session.Property("IISSITENAME");
    Session.Property("IISSITENAME") = "";
    Session.Property("IISSITESAVAILABLE") = "";
    var view = null;

    try
    {
        var database = Session.Database;
        view = database.OpenView("DELETE FROM `ComboBox` WHERE `Property` = 'IISSITENAME'");
        view.Execute();
        view.Close();
        view = null;

        var manager = new ActiveXObject("Microsoft.ApplicationHost.WritableAdminManager");
        var sites = manager.GetAdminSection("system.applicationHost/sites", "MACHINE/WEBROOT/APPHOST").Collection;
        if (sites.Count === 0)
        {
            Session.Property("IISSITESTATUS") =
                "No IIS websites exist. Create one in IIS Manager, then return to this page.";
            return 1;
        }

        view = database.OpenView("SELECT `Property`, `Order`, `Value`, `Text` FROM `ComboBox`");
        view.Execute();
        var selected = "";
        for (var index = 0; index < sites.Count; index++)
        {
            var name = String(sites.Item(index).Properties.Item("name").Value);
            var row = Session.Installer.CreateRecord(4);
            row.StringData(1) = "IISSITENAME";
            row.IntegerData(2) = index + 1;
            row.StringData(3) = name;
            row.StringData(4) = name;
            view.Modify(7, row); // Temporary rows belong only to this setup session.
            if (name.toLowerCase() === previous.toLowerCase())
            {
                selected = name;
            }
        }

        Session.Property("IISSITENAME") = selected;
        Session.Property("IISSITESAVAILABLE") = "1";
        Session.Property("IISSITESTATUS") = "Select an existing IIS website.";
    }
    catch (error)
    {
        Session.Property("IISSITESTATUS") =
            "Could not list IIS websites. Run setup as an administrator and verify IIS is configured.";
        var message = Session.Installer.CreateRecord(1);
        message.StringData(0) = "OpenTimeStamp: could not list IIS websites. [1]";
        message.StringData(1) = String(error.description || error.message);
        Session.Message(0x04000000, message);
    }
    finally
    {
        if (view !== null)
        {
            view.Close();
        }
    }

    return 1;
}

function LoadIisApplications()
{
    Session.Property("IISAPPLICATIONSAVAILABLE") = "";
    var view = null;

    try
    {
        var database = Session.Database;
        view = database.OpenView("DELETE FROM `ComboBox` WHERE `Property` = 'APPLICATIONNAME'");
        view.Execute();
        view.Close();
        view = null;

        var siteName = Session.Property("IISSITENAME");
        var manager = new ActiveXObject("Microsoft.ApplicationHost.WritableAdminManager");
        var sites = manager.GetAdminSection("system.applicationHost/sites", "MACHINE/WEBROOT/APPHOST").Collection;
        var applications = null;
        for (var index = 0; index < sites.Count; index++)
        {
            var site = sites.Item(index);
            if (String(site.Properties.Item("name").Value).toLowerCase() === siteName.toLowerCase())
            {
                applications = site.Collection;
                break;
            }
        }
        if (applications === null)
        {
            Session.Property("IISAPPLICATIONSTATUS") =
                "The selected website no longer exists. Go Back and select an existing website.";
            return 1;
        }

        view = database.OpenView("SELECT `Property`, `Order`, `Value`, `Text` FROM `ComboBox`");
        view.Execute();
        var selected = Session.Property("APPLICATIONNAME");
        for (var index = 0; index < applications.Count; index++)
        {
            var name = String(applications.Item(index).Properties.Item("path").Value).substring(1);
            // Setup deploys named, single-segment applications rather than the website root.
            if (!/^[A-Za-z0-9._-]{1,64}$/.test(name) || /\.$/.test(name) ||
                new RegExp("^(bin|App_Data|App_Code|App_GlobalResources|App_LocalResources|" +
                    "App_WebReferences|App_Browsers|web\\.config|\\.git|\\.svn)$", "i").test(name))
            {
                continue;
            }
            var row = Session.Installer.CreateRecord(4);
            row.StringData(1) = "APPLICATIONNAME";
            row.IntegerData(2) = index + 1;
            row.StringData(3) = name;
            row.StringData(4) = name;
            view.Modify(7, row);
            if (name.toLowerCase() === selected.toLowerCase())
            {
                selected = name;
            }
        }

        Session.Property("APPLICATIONNAME") = selected;
        Session.Property("IISAPPLICATIONSAVAILABLE") = "1";
        Session.Property("IISAPPLICATIONSTATUS") =
            "Paths start with / and allow letters, numbers, underscores, hyphens, and slashes. " +
            "Administration uses /admin.";
    }
    catch (error)
    {
        Session.Property("IISAPPLICATIONSTATUS") =
            "Could not list applications. Check IIS configuration, then go Back and try again.";
        var message = Session.Installer.CreateRecord(1);
        message.StringData(0) = "OpenTimeStamp: could not list IIS applications. [1]";
        message.StringData(1) = String(error.description || error.message);
        Session.Message(0x04000000, message);
    }
    finally
    {
        if (view !== null)
        {
            view.Close();
        }
    }

    return 1;
}
