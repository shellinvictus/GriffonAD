#!/usr/bin/env python3
# This script generates an xml task, it tries to mimic as much as possible
# a real generated xml.

import uuid
import argparse
from time import gmtime, strftime
from xml.sax.saxutils import escape as xml_escape


XML_HEADER = '<?xml version="1.0" encoding="utf-8"?>\n'

TRIGGERS = """"""

TASK_1_1 = """<ScheduledTasks clsid="{{CC63F200-7309-4ba0-B154-A71CD118DBCC}}">
<TaskV2 clsid="{{D8896631-B747-47a7-84A6-C155337F3BC8}}" name="{taskname}" image="0" changed="{date}" uid="{uuid}" userContext="0" removePolicy="0">
    <Properties action="C" name="{taskname}" runAs="{runas}" logonType="{logontype}">
        <Task version="1.1">
            <RegistrationInfo>
                <Author>{author}</Author>
                <Description>{description}</Description>
            </RegistrationInfo>
            <Principals>
                <Principal id="Author">
                    <UserId>{runas}</UserId>
                    <LogonType>{logontype}</LogonType>
                    <RunLevel>{runlevel}</RunLevel>
                </Principal>
            </Principals>
            <Settings>
                <IdleSettings>
                    <Duration>PT5M</Duration>
                    <WaitTimeout>PT1H</WaitTimeout>
                    <StopOnIdleEnd>false</StopOnIdleEnd>
                    <RestartOnIdle>false</RestartOnIdle>
                </IdleSettings>
                <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                <DisallowStartIfOnBatteries>{battery}</DisallowStartIfOnBatteries>
                <StopIfGoingOnBatteries>{battery}</StopIfGoingOnBatteries>
                <AllowHardTerminate>false</AllowHardTerminate>
                <AllowStartOnDemand>false</AllowStartOnDemand>
                <Enabled>true</Enabled>
                <Hidden>false</Hidden>
                <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
                <Priority>7</Priority>
            </Settings>
            <Triggers>
                <TimeTrigger>
                    {start}
                    <Enabled>true</Enabled>
                </TimeTrigger>
            </Triggers>
            <Actions Context="Author">
                <Exec>
                    <Command>{command}</Command>
                    {args}
                </Exec>
            </Actions>
        </Task>
    </Properties>
    {filters}
</TaskV2>"""

TASK_1_2 = """<ScheduledTasks clsid="{{CC63F200-7309-4ba0-B154-A71CD118DBCC}}">
<ImmediateTaskV2 clsid="{{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}}" name="{taskname}" image="0" userContext="0" removePolicy="0" changed="{date}" uid="{uuid}">
    <Properties action="C" name="{taskname}" runAs="{runas}" logonType="{logontype}">
        <Task version="1.2">
            <RegistrationInfo>
                <Author>{author}</Author>
                <Description>{description}</Description>
            </RegistrationInfo>
            <Principals>
                <Principal id="Author">
                    <UserId>{runas}</UserId>
                    <LogonType>{logontype}</LogonType>
                    <RunLevel>{runlevel}</RunLevel>
                </Principal>
            </Principals>
            <Settings>
                <IdleSettings>
                    <Duration>PT5M</Duration>
                    <WaitTimeout>PT1H</WaitTimeout>
                    <StopOnIdleEnd>false</StopOnIdleEnd>
                    <RestartOnIdle>false</RestartOnIdle>
                </IdleSettings>
                <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
                <AllowHardTerminate>false</AllowHardTerminate>
                <StartWhenAvailable>true</StartWhenAvailable>
                <AllowStartOnDemand>false</AllowStartOnDemand>
                <Enabled>true</Enabled>
                <Hidden>false</Hidden>
                <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
                <Priority>7</Priority>
                <DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>
            </Settings>
            <Triggers>
                <TimeTrigger>
                    {start}
                    <Enabled>true</Enabled>
                </TimeTrigger>
            </Triggers>
            <Actions Context="Author">
                <Exec>
                    <Command>{command}</Command>
                    {args}
                </Exec>
            </Actions>
        </Task>
    </Properties>
    {filters}
</ImmediateTaskV2>"""

TASK_1_3 = """<ScheduledTasks clsid="{{CC63F200-7309-4ba0-B154-A71CD118DBCC}}">
<ImmediateTaskV2 clsid="{{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}}" name="{taskname}" image="0" changed="{date}" uid="{uuid}" userContext="0" removePolicy="0">
    <Properties action="C" name="{taskname}" runAs="{runas}" logonType="{logontype}">
        <Task version="1.3">
            <RegistrationInfo>
                <Author>{author}</Author>
                <Description>{description}</Description>
            </RegistrationInfo>
            <Principals>
                <Principal id="Author">
                    <UserId>{runas}</UserId>
                    <LogonType>{logontype}</LogonType>
                    <RunLevel>{runlevel}</RunLevel>
                </Principal>
            </Principals>
            <Settings>
                <IdleSettings>
                    <Duration>PT5M</Duration>
                    <WaitTimeout>PT1H</WaitTimeout>
                    <StopOnIdleEnd>false</StopOnIdleEnd>
                    <RestartOnIdle>false</RestartOnIdle>
                </IdleSettings>
                <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                <DisallowStartIfOnBatteries>{battery}</DisallowStartIfOnBatteries>
                <StopIfGoingOnBatteries>{battery}</StopIfGoingOnBatteries>
                <AllowHardTerminate>false</AllowHardTerminate>
                <StartWhenAvailable>true</StartWhenAvailable>
                <AllowStartOnDemand>false</AllowStartOnDemand>
                <Enabled>true</Enabled>
                <Hidden>{hidden}</Hidden>
                <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
                <Priority>7</Priority>
                <DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>
            </Settings>
            <Triggers>
                <TimeTrigger>
                    {start}
                    <Enabled>true</Enabled>
                </TimeTrigger>
            </Triggers>
            <Actions Context="Author">
                <Exec>
                    <Command>{command}</Command>
                    {args}
                </Exec>
            </Actions>
            {filters}
        </Task>
    </Properties>
</ImmediateTaskV2>"""

END = "\n</ScheduledTasks>\n"

TASK_1_3 = XML_HEADER + TASK_1_3.replace('    ', '').replace('\n', '') + END
TASK_1_2 = XML_HEADER + TASK_1_2.replace('    ', '').replace('\n', '') + END
TASK_1_1 = XML_HEADER + TASK_1_1.replace('    ', '').replace('\n', '') + END
TRIGGERS = TRIGGERS.replace('    ', '').replace('\n', '')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--taskname', type=str, default='taskname')
    parser.add_argument('--description', type=str, default='description')
    parser.add_argument('--author', type=str, default='DOMAIN\\Administrator',
            help='By default the domain is NOT the fqdn')
    parser.add_argument('--run-as-system', action='store_true')
    parser.add_argument('--run-as-user', action='store_true')
    parser.add_argument('--no-run-on-battery', action='store_true')
    parser.add_argument('--hidden', action='store_true', help='default is false')
    parser.add_argument('--logontype', type=str, default='InteractiveToken',
            choices=['InteractiveToken', 'S4U'],
            help='InteractiveToken = Run only when user is logged on (default)\n'
                 'S4U = Run whether user is logged or not')
    parser.add_argument('--runlevel', type=str, default='l', choices=['h', 'l'],
            help='h = HighestAvailable\n'
                 'l = LeastPrivilege (default)')
    parser.add_argument('--cmd', type=str, default='C:\\absolute\\path',
            help='Example: \'C:\\Windows\\System32\\cmd.exe\'')
    parser.add_argument('--args', type=str, default='',
            help='Example: \'/c "cmd1 & cmd2 & cmd3"\'\n'
                 'To add an admin you can intead modify the GptTmpl.inf to add a user in the administrator group.')
    parser.add_argument('--version', type=str, default='1.2', choices=['1.1', '1.2', '1.3'],
            help='1.3: Windows 7 / Windows Server 2008R2\n'
                 '1.2: Windows Vista or Windows Server 2008 (default)\n'
                 '1.1: Windows Server 2003 or Windows XP or Windows 2000\n')
    parser.add_argument('--start-at', type=str, default='immediate',
            help='Example: "2025-01-25T13:18:52" (time is UTC)\n'
                 'You can also set "--start-at immediate" for an immediate task')
    parser.add_argument('--filter', type=str, metavar='NAME',
            help='Execute the task only for the target, add the $ at the end if it\'s a computer')
    parser.add_argument('--filter-sid', type=str, metavar='SID',
            help='Required only if filter is a user')

    args = parser.parse_args()

    uuid = '{' + str(uuid.uuid4()).upper() + '}'
    date = strftime("%Y-%m-%d %H:%M:%S", gmtime())

    if args.run_as_system and args.run_as_user:
        print('error: can\'t have run_as_system and run_as_user')
        exit(0)

    if args.run_as_system:
        runas = 'NT AUTHORITY\\System'
    elif args.run_as_user:
        runas = '%LogonDomain%\\%LogonUser%'

    if args.version == '1.3':
        task = TASK_1_3
    elif args.version == '1.2':
        task = TASK_1_2
    elif args.version == '1.1':
        task = TASK_1_1

    if args.start_at == 'immediate':
        start = '<StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary>'
    else:
        start = f'<StartBoundary>{args.start_at}</StartBoundary>'
        task = task.replace('</Triggers>', '\n\t\t\t\t</Triggers>')

    task = task.replace('</Actions>', '\n\t\t\t\t</Actions>')

    if args.filter:
        if args.filter[-1] == '$':
            filters = f'<Filters><FilterComputer bool="AND" not="0" type="NETBIOS" name="{args.filter.replace("$", "")}"/></Filters>'
        else:
            if not args.filter_sid:
                print('error: --filter-sid is missing for user')
                exit(0)
            filters = f'<Filters><FilterUser bool="AND" not="0" name="{args.filter}" sid="{args.filter_sid}"/></Filters>'
    else:
        filters = ''

    task = task.format(
        uuid=uuid,
        date=date,
        author=xml_escape(args.author),
        taskname=xml_escape(args.taskname),
        description=xml_escape(args.description),
        logontype=args.logontype,
        runas=runas,
        hidden='true' if args.hidden else 'false',
        runlevel='HighestAvailable' if args.runlevel == 'h' else 'LeastPrivilege',
        command=xml_escape(args.cmd),
        args=f'<Arguments>{xml_escape(args.args)}</Arguments>' if args.args else '',
        battery = 'true' if args.no_run_on_battery else 'false',
        filters=filters,
        start=start,
    )

    task = task.replace('\n', '\r\n')

    print(task, end='')
