import classes from './LeftDiv.module.css';
import Button from './Button';
const LeftDiv = (props) => {
  const buttons = [
    {id:1, label:'Credential Access'},
    {id:2, label:'Persistence'},
    {id:3, label:'Impact'},
    {id:4, label:'Execution'},
    {id:5, label:'Lateral Movement'},
    {id:6, label:'Exfiltration'},
  ]
  return (
    <div className={classes.leftDiv}>
      <div className={classes.top_part}>
        <div className={classes.title}><p>SOC DETECTION LAB</p></div>
        <div className={classes.overview}>
          <p>A comprehensive collection of production-grade Splunk detection rules covering 6 MITRE ATT&CK tactics.
          Each detection includes basic and enhanced versions with dynamic severity, false positive reduction, and investigation guidance. Designed to demonstrate practical SOC
          analyst skills including threat detection, alert engineering, and incident response workflow
          </p>
        </div>
      </div>
      <div className={classes.bottom_part}>
        <div className={classes.header}><p>MITRE TACTIC</p></div>
        <div className={classes.button_div}>
          {buttons.map(button => <Button forwardHandler={props.forwardHandler} id={button.id} key={button.id} label={button.label}/>)}
        </div>
      </div>
    </div>
  )
}
export default LeftDiv;
