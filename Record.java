/**
 * This is an auxiliary class used to represents records of labeled passwords
 * stored in the vault file.
 */
public class Record {

    private final String label;
    private final String password;

    public Record(String labelValue, String passwordValue) {
        this.label = labelValue;
        this.password = passwordValue;
    }

    public String getLabel() {
        return label;
    }

    public String getPassword() {
        return password;
    }

    @Override
    public String toString() {
        return label + ": " +  password;
    }

}